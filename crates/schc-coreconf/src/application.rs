//! Generic CORECONF application service and datagram client.
//!
//! The service owns a rustconf datastore and accepts one serialized CoAP
//! datagram at a time.
//! The client is a small UDP adapter that sends normal CoAP requests to the
//! core application endpoint.

use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use coap_lite::{
    CoapOption, ContentFormat, MessageClass, MessageType, Packet, RequestType, ResponseType,
};
use coreconf_model::{CompositeModel, CoreconfError};
use coreconf_runtime::request_handler::RequestHandler;
use coreconf_runtime::transport::coap_lite::{
    packet_to_request, response_to_packet, CoapLiteClient, CoreconfClient,
};
use coreconf_runtime::Datastore;
use serde_json::Value;
use thiserror::Error;

/// Errors returned by the application service and client.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// A file containing a SID model or datastore could not be read.
    #[error("application file operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// The rustconf model or datastore rejected input.
    #[error("application model operation failed: {0}")]
    Model(#[from] CoreconfError),
    /// A CoAP datagram could not be parsed or serialized.
    #[error("CoAP datagram operation failed: {0}")]
    Coap(String),
    /// A remote server returned a non-success response.
    #[error("remote CORECONF response was {code}: {message}")]
    Remote {
        /// The CoAP response code.
        code: String,
        /// The optional response payload rendered as text.
        message: String,
    },
    /// A command value was not valid JSON.
    #[error("invalid JSON value: {0}")]
    Json(#[from] serde_json::Error),
}

/// A rustconf-backed generic application datastore service.
///
/// `GenericDataService` deliberately has no socket.
/// The device feeds reconstructed application CoAP datagrams into
/// [`Self::handle_datagram`], keeping the SCHC link as the only device
/// transport boundary.
pub struct GenericDataService {
    resource_path: String,
    model: CompositeModel,
    handler: RequestHandler,
}

impl GenericDataService {
    /// Loads one or more SID files and a JSON datastore from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if a file is unreadable, a SID file is malformed, or
    /// the datastore does not conform to the composed model.
    pub fn from_files(
        sid_paths: &[PathBuf],
        data_path: impl AsRef<Path>,
        resource_path: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        if sid_paths.is_empty() {
            return Err(ApplicationError::Model(CoreconfError::ValidationError(
                "at least one application SID file is required".to_owned(),
            )));
        }
        let sid_contents: Vec<String> = sid_paths
            .iter()
            .map(fs::read_to_string)
            .collect::<Result<_, _>>()?;
        let sid_refs: Vec<&str> = sid_contents.iter().map(String::as_str).collect();
        let model = CompositeModel::from_sid_strings(&sid_refs)?;
        let data = fs::read_to_string(data_path)?;
        Self::from_model_and_json(model, &data, resource_path)
    }

    /// Builds a service from in-memory SID documents and datastore JSON.
    ///
    /// This constructor is useful for deterministic protocol tests and for
    /// callers that obtain model data from a source other than a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the SID documents or datastore JSON is invalid.
    pub fn from_sid_contents(
        sid_contents: &[&str],
        data_json: &str,
        resource_path: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        if sid_contents.is_empty() {
            return Err(ApplicationError::Model(CoreconfError::ValidationError(
                "at least one application SID document is required".to_owned(),
            )));
        }
        let model = CompositeModel::from_sid_strings(sid_contents)?;
        Self::from_model_and_json(model, data_json, resource_path)
    }

    /// Builds a service from a composed model and datastore JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the datastore JSON cannot be decoded.
    pub fn from_model_and_json(
        model: CompositeModel,
        data_json: &str,
        resource_path: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        let datastore = Datastore::from_json_with_model(model.clone(), data_json)?;
        Ok(Self {
            resource_path: normalize_resource_path(&resource_path.into()),
            model,
            handler: RequestHandler::new(datastore),
        })
    }

    /// Returns the composed application model used by this service.
    #[must_use]
    pub const fn model(&self) -> &CompositeModel {
        &self.model
    }

    /// Returns the current identifier-keyed datastore tree.
    #[must_use]
    pub fn snapshot(&self) -> Value {
        self.handler.datastore().get_all()
    }

    /// Returns the rustconf datastore owned by this service.
    #[must_use]
    pub fn datastore(&self) -> &Datastore {
        self.handler.datastore()
    }

    /// Handles one complete CoAP UDP datagram and returns its response.
    ///
    /// Discovery is handled locally, while all CORECONF requests are routed
    /// through rustconf's public conversion functions and `RequestHandler`.
    /// Response message ID and token are copied from the request by the
    /// rustconf conversion layer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed CoAP or an unrepresentable response.
    pub fn handle_datagram(&mut self, datagram: &[u8]) -> Result<Vec<u8>, ApplicationError> {
        let request = Packet::from_bytes(datagram)
            .map_err(|error| ApplicationError::Coap(error.to_string()))?;
        let response = if uri_path(&request) == "/.well-known/core" {
            self.discovery_response(&request)
        } else {
            let response = match packet_to_request(&request, &self.resource_path) {
                Ok(request) => self.handler.handle(&request),
                Err(response) => response,
            };
            response_to_packet(&request, response)
        };
        response
            .to_bytes()
            .map_err(|error| ApplicationError::Coap(error.to_string()))
    }

    fn discovery_response(&self, request: &Packet) -> Packet {
        let management = self.resource_path.trim_matches('/');
        let streaming = if management == "c" {
            "s".to_owned()
        } else {
            format!("{management}/s")
        };
        let mut response = Packet::new();
        response.header.message_id = request.header.message_id;
        response.header.set_type(response_type_for(request));
        response.set_token(request.get_token().to_vec());
        if matches!(request.header.code, MessageClass::Request(RequestType::Get)) {
            response.header.code = MessageClass::Response(ResponseType::Content);
            response.payload = format!(
                "</{management}>;rt=\"core.c.ds\";ct=140;ds=1029,</{streaming}>;rt=\"core.c.ev\";ct=142;obs"
            )
            .into_bytes();
            response.set_content_format(ContentFormat::ApplicationLinkFormat);
        } else {
            response.header.code = MessageClass::Response(ResponseType::MethodNotAllowed);
        }
        response
    }
}

/// A normal CoAP UDP client for a device-owned CORECONF datastore.
///
/// rustconf owns discovery, root GET, root FETCH, and mutation packet
/// construction through its public [`CoreconfClient`] implementation.
pub struct DataClient {
    client: CoapLiteClient,
    endpoint: SocketAddr,
    model: CompositeModel,
}

impl DataClient {
    /// Connects to a core application endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint cannot be resolved or the UDP socket
    /// cannot be configured.
    pub fn connect(
        model: CompositeModel,
        endpoint: impl ToSocketAddrs,
        resource_path: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        let resource_path = normalize_resource_path(&resource_path.into());
        let client = CoapLiteClient::connect(model.clone(), endpoint, resource_path)?;
        Self::from_client(model, client)
    }

    /// Connects to a core application endpoint using an explicit local address.
    ///
    /// The local address controls both the UDP source address and source port.
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint cannot be resolved or the UDP socket
    /// cannot be bound or configured.
    pub fn connect_bound(
        model: CompositeModel,
        local_addr: SocketAddr,
        endpoint: impl ToSocketAddrs,
        resource_path: impl Into<String>,
    ) -> Result<Self, ApplicationError> {
        let resource_path = normalize_resource_path(&resource_path.into());
        let client =
            CoapLiteClient::connect_bound(model.clone(), local_addr, endpoint, resource_path)?;
        Self::from_client(model, client)
    }

    fn from_client(
        model: CompositeModel,
        client: CoapLiteClient,
    ) -> Result<Self, ApplicationError> {
        let endpoint = client.endpoint().to_owned();
        let endpoint = endpoint.parse::<SocketAddr>().map_err(|error| {
            ApplicationError::Coap(format!(
                "connected endpoint {endpoint:?} is not a socket address: {error}"
            ))
        })?;
        Ok(Self {
            client,
            endpoint,
            model,
        })
    }

    /// Returns the connected core endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns deterministic schema lines, optionally filtered by substring.
    #[must_use]
    pub fn schema(&self, filter: Option<&str>) -> Vec<String> {
        schema_lines(&self.model, filter)
    }

    /// Performs CORE Link Format discovery.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, malformed CoAP, or non-success status.
    pub fn discover(&mut self, query: Option<&str>) -> Result<String, ApplicationError> {
        self.client
            .discover(Some(query.unwrap_or("d=0")))
            .map_err(ApplicationError::from)
    }

    /// Performs a root CoAP GET, validates the complete snapshot locally, and
    /// selects one value from the requested path.
    ///
    /// A missing selected path is represented as `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, decoding, model validation, or another
    /// response status.
    pub fn get(&mut self, path: &str) -> Result<Option<Value>, ApplicationError> {
        let path = canonical_path(path);
        let snapshot = self
            .client
            .fetch_snapshot()
            .map_err(ApplicationError::from)?;
        let datastore = Datastore::from_json_with_model(self.model.clone(), &snapshot.to_string())?;
        datastore.get_path(&path).map_err(ApplicationError::from)
    }

    /// Performs a root CoAP FETCH using the public rustconf client and decodes
    /// its selected CORECONF instance value.
    ///
    /// This method emits the FETCH CoAP method code and does not alias GET.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, decoding, or another response status.
    pub fn fetch(&mut self, path: &str) -> Result<Option<Value>, ApplicationError> {
        let path = canonical_path(path);
        self.client
            .fetch_path(&path)
            .map_err(ApplicationError::from)
    }

    /// Sends an immediate CORECONF iPATCH mutation for one path.
    ///
    /// # Errors
    ///
    /// Returns an error for model conversion, transport, or a non-success
    /// response.
    pub fn set(&mut self, path: &str, value: Value) -> Result<(), ApplicationError> {
        let path = canonical_path(path);
        let wire_value = self
            .model
            .identifier_value_to_sid_value_at_path(value, &path)?;
        self.client
            .apply_patch(&[(path, Some(wire_value))])
            .map_err(ApplicationError::from)
    }

    /// Sends an immediate root CORECONF iPATCH deletion for one path.
    ///
    /// # Errors
    ///
    /// Returns an error for transport or a non-success response.
    pub fn delete(&mut self, path: &str) -> Result<(), ApplicationError> {
        let path = canonical_path(path);
        self.client
            .apply_patch(&[(path, None)])
            .map_err(ApplicationError::from)
    }

    /// Performs a full remote GET and returns the refreshed snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, decoding, or a non-success response.
    pub fn reload(&mut self) -> Result<Value, ApplicationError> {
        self.client.fetch_snapshot().map_err(ApplicationError::from)
    }
}

/// Returns sorted, human-readable schema entries from every SID file in a
/// composed model.
#[must_use]
pub fn schema_lines(model: &CompositeModel, filter: Option<&str>) -> Vec<String> {
    let mut entries: Vec<(String, i64)> = model
        .sids
        .iter()
        .filter_map(|(identifier, sid)| {
            identifier
                .starts_with('/')
                .then_some((identifier.clone(), *sid))
        })
        .filter(|(identifier, _)| filter.is_none_or(|filter| identifier.contains(filter)))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
        .into_iter()
        .map(|(identifier, sid)| format!("{identifier} (sid {sid})"))
        .collect()
}

fn normalize_resource_path(path: &str) -> String {
    let path = path.trim_matches('/');
    if path.is_empty() {
        "c".to_owned()
    } else {
        path.to_owned()
    }
}

fn canonical_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

#[cfg(test)]
fn add_uri_path(packet: &mut Packet, path: &str) {
    for segment in path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
    {
        packet.add_option(CoapOption::UriPath, segment.as_bytes().to_vec());
    }
}

fn uri_path(packet: &Packet) -> String {
    let path = packet
        .get_option(CoapOption::UriPath)
        .map(|options| {
            options
                .iter()
                .filter_map(|value| std::str::from_utf8(value).ok())
                .collect::<Vec<_>>()
                .join("/")
        })
        .unwrap_or_default();
    format!("/{path}")
}

fn response_type_for(request: &Packet) -> MessageType {
    match request.header.get_type() {
        MessageType::Confirmable => MessageType::Acknowledgement,
        MessageType::NonConfirmable => MessageType::NonConfirmable,
        MessageType::Acknowledgement | MessageType::Reset => MessageType::Confirmable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coap_lite::RequestType;

    const SID: &str = include_str!("../../../fixtures/demo/demo-data.sid");
    const DATA: &str = include_str!("../../../fixtures/demo/app-data.json");
    const EXTRA_SID: &str = r#"{
        "module-name": "extra-data",
        "module-revision": "2026-07-14",
        "item": [
            {"namespace": "module", "identifier": "extra-data", "sid": 61000},
            {"namespace": "data", "identifier": "/extra-data:status", "sid": 61001, "type": "string"}
        ],
        "key-mapping": {}
    }"#;

    #[test]
    fn identifier_paths_round_trip_with_multiple_sid_files() {
        let model = CompositeModel::from_sid_strings(&[SID, EXTRA_SID]).expect("composed model");
        let service = GenericDataService::from_model_and_json(
            model.clone(),
            r#"{
                "demo-data:config": {
                    "count": 7,
                    "enabled": true,
                    "name": "sample-device",
                    "threshold": -2
                },
                "extra-data:status": "online"
            }"#,
            "c",
        )
        .expect("service");
        let snapshot = service.snapshot();
        assert_eq!(
            service
                .datastore()
                .get_path("/demo-data:config/count")
                .expect("datastore path"),
            Some(Value::from(7))
        );
        let wire = model
            .identifier_value_to_sid_value(snapshot.clone())
            .expect("SID encoding");
        assert_eq!(
            model
                .sid_value_to_identifier_value(wire)
                .expect("SID decoding"),
            snapshot
        );
        let unknown = serde_json::json!({"99999": 1});
        assert_eq!(
            model
                .sid_value_to_identifier_value(unknown.clone())
                .expect("unknown SID"),
            unknown
        );
        assert_eq!(service.model().get_sid("/extra-data:status"), Some(61001));
    }

    #[test]
    fn schema_is_sorted_and_filterable() {
        let service = GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
        let all = schema_lines(service.model(), None);
        assert_eq!(all, {
            let mut sorted = all.clone();
            sorted.sort();
            sorted
        });
        assert!(all
            .iter()
            .any(|line| line.contains("/demo-data:config/count")));
        let filtered = schema_lines(service.model(), Some("enabled"));
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].contains("/demo-data:config/enabled"));
    }

    fn discovery_request(method: RequestType, message_id: u16, token: &[u8]) -> Packet {
        let mut request = Packet::new();
        request.header.message_id = message_id;
        request.header.code = MessageClass::Request(method);
        request.header.set_type(MessageType::Confirmable);
        request.set_token(token.to_vec());
        add_uri_path(&mut request, "/.well-known/core");
        request.add_option(CoapOption::UriQuery, b"d=0".to_vec());
        request
    }

    fn content_formats(packet: &Packet) -> Vec<u16> {
        packet
            .get_option(CoapOption::ContentFormat)
            .into_iter()
            .flatten()
            .map(|value| {
                value
                    .iter()
                    .fold(0_u16, |number, byte| number << 8 | u16::from(*byte))
            })
            .collect()
    }

    #[test]
    fn discovery_response_matches_rustconf_contract() {
        let mut service =
            GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
        let request = discovery_request(RequestType::Get, 0x3456, &[0xc1, 0xd2]);
        let response = Packet::from_bytes(
            &service
                .handle_datagram(&request.to_bytes().expect("request bytes"))
                .expect("response bytes"),
        )
        .expect("response");

        assert_eq!(
            response.header.code,
            MessageClass::Response(ResponseType::Content)
        );
        assert_eq!(response.header.get_type(), MessageType::Acknowledgement);
        assert_eq!(response.header.message_id, 0x3456);
        assert_eq!(response.get_token(), &[0xc1, 0xd2]);
        assert_eq!(content_formats(&response), vec![40]);
        assert_eq!(
            response.payload.as_slice(),
            b"</c>;rt=\"core.c.ds\";ct=140;ds=1029,</s>;rt=\"core.c.ev\";ct=142;obs"
        );
    }

    #[test]
    fn discovery_rejects_non_get_methods() {
        let methods = [
            RequestType::Post,
            RequestType::Put,
            RequestType::Delete,
            RequestType::Fetch,
            RequestType::Patch,
            RequestType::IPatch,
        ];
        let mut service =
            GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");

        for (index, method) in (0_u8..).zip(methods) {
            let message_id = 0x1000 + u16::from(index);
            let token = [index, 0xa5];
            let request = discovery_request(method, message_id, &token);
            let response = Packet::from_bytes(
                &service
                    .handle_datagram(&request.to_bytes().expect("request bytes"))
                    .expect("response bytes"),
            )
            .expect("response");

            assert_eq!(
                response.header.code,
                MessageClass::Response(ResponseType::MethodNotAllowed),
                "method {method:?}"
            );
            assert_eq!(response.header.get_type(), MessageType::Acknowledgement);
            assert_eq!(response.header.message_id, message_id);
            assert_eq!(response.get_token(), token);
            assert!(response.payload.is_empty());
            assert!(content_formats(&response).is_empty());
        }
    }

    #[test]
    fn discovery_response_preserves_custom_resource_paths() {
        let mut service =
            GenericDataService::from_sid_contents(&[SID], DATA, "mgmt").expect("service");
        let request = discovery_request(RequestType::Get, 0x4567, &[0x01]);
        let response = Packet::from_bytes(
            &service
                .handle_datagram(&request.to_bytes().expect("request bytes"))
                .expect("response bytes"),
        )
        .expect("response");

        assert_eq!(content_formats(&response), vec![40]);
        assert_eq!(
            response.payload.as_slice(),
            b"</mgmt>;rt=\"core.c.ds\";ct=140;ds=1029,</mgmt/s>;rt=\"core.c.ev\";ct=142;obs"
        );
    }

    #[test]
    fn obsolete_path_fetch_is_rejected() {
        let mut service =
            GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
        let mut request = Packet::new();
        request.header.message_id = 77;
        request.header.code = MessageClass::Request(RequestType::Fetch);
        request.header.set_type(MessageType::Confirmable);
        request.set_token(vec![1, 2]);
        add_uri_path(&mut request, "/c/demo-data:config/count");
        let bytes = request.to_bytes().expect("request bytes");
        let response =
            Packet::from_bytes(&service.handle_datagram(&bytes).expect("response bytes"))
                .expect("response");
        assert_eq!(response.header.message_id, 77);
        assert_eq!(response.get_token(), &[1, 2]);
        assert_eq!(
            response.header.code,
            MessageClass::Response(ResponseType::MethodNotAllowed)
        );
    }

    #[test]
    fn public_client_bound_ipv6_uses_exact_source_and_returns_value() {
        use std::io::ErrorKind;
        use std::net::{Ipv6Addr, UdpSocket};
        use std::sync::mpsc;
        use std::thread;

        let server_socket = match UdpSocket::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)) {
            Ok(socket) => socket,
            Err(error) if error.kind() == ErrorKind::AddrNotAvailable => return,
            Err(error) => panic!("IPv6 loopback server socket: {error}"),
        };
        let server_address = server_socket.local_addr().expect("server address");
        let source_reservation =
            match UdpSocket::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0)) {
                Ok(socket) => socket,
                Err(error) if error.kind() == ErrorKind::AddrNotAvailable => return,
                Err(error) => panic!("IPv6 loopback client socket: {error}"),
            };
        let local_address = source_reservation.local_addr().expect("client address");
        assert_ne!(local_address.port(), 0);
        drop(source_reservation);

        let (peer_sender, peer_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut service =
                GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
            let mut buffer = vec![0_u8; 65_535];
            let (length, peer) = server_socket.recv_from(&mut buffer).expect("request");
            peer_sender.send(peer).expect("peer");
            let response = service
                .handle_datagram(&buffer[..length])
                .expect("service response");
            server_socket.send_to(&response, peer).expect("response");
        });

        let model = CompositeModel::from_sid_strings(&[SID]).expect("model");
        let mut client = DataClient::connect_bound(model, local_address, server_address, "c")
            .expect("bound client");
        assert_eq!(
            client.get("/demo-data:config/count").expect("GET"),
            Some(Value::from(7))
        );
        assert_eq!(peer_receiver.recv().expect("peer"), local_address);
        server.join().expect("server");
    }

    #[test]
    fn public_client_uses_later_endpoint_candidate_and_reports_actual_peer() {
        use std::net::UdpSocket;
        use std::thread;

        let failing_endpoint: SocketAddr = "255.255.255.255:5683".parse().expect("address");
        let probe = UdpSocket::bind("127.0.0.1:0").expect("probe socket");
        assert!(
            probe.connect(failing_endpoint).is_err(),
            "broadcast UDP destination unexpectedly accepted"
        );
        let server_socket = UdpSocket::bind("127.0.0.1:0").expect("server socket");
        let server_address = server_socket.local_addr().expect("server address");
        let endpoints = [failing_endpoint, server_address];
        let server = thread::spawn(move || {
            let mut service =
                GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
            let mut buffer = vec![0_u8; 65_535];
            let (length, peer) = server_socket.recv_from(&mut buffer).expect("request");
            let response = service
                .handle_datagram(&buffer[..length])
                .expect("service response");
            server_socket.send_to(&response, peer).expect("response");
        });

        let model = CompositeModel::from_sid_strings(&[SID]).expect("model");
        let mut client = DataClient::connect(model, &endpoints[..], "c").expect("client");
        assert_eq!(client.endpoint(), server_address);
        assert_eq!(
            client.get("/demo-data:config/count").expect("GET"),
            Some(Value::from(7))
        );
        server.join().expect("server");
    }

    #[test]
    fn public_bound_client_uses_later_endpoint_and_preserves_source() {
        use std::net::UdpSocket;
        use std::sync::mpsc;
        use std::thread;

        let failing_endpoint: SocketAddr = "255.255.255.255:5683".parse().expect("address");
        let probe = UdpSocket::bind("127.0.0.1:0").expect("probe socket");
        assert!(
            probe.connect(failing_endpoint).is_err(),
            "broadcast UDP destination unexpectedly accepted"
        );
        let server_socket = UdpSocket::bind("127.0.0.1:0").expect("server socket");
        let server_address = server_socket.local_addr().expect("server address");
        let reserved = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        let local_address = reserved.local_addr().expect("client address");
        assert_ne!(local_address.port(), 0);
        drop(reserved);
        let endpoints = [failing_endpoint, server_address];
        let (peer_sender, peer_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut service =
                GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
            let mut buffer = vec![0_u8; 65_535];
            let (length, peer) = server_socket.recv_from(&mut buffer).expect("request");
            peer_sender.send(peer).expect("peer");
            let response = service
                .handle_datagram(&buffer[..length])
                .expect("service response");
            server_socket.send_to(&response, peer).expect("response");
        });

        let model = CompositeModel::from_sid_strings(&[SID]).expect("model");
        let mut client =
            DataClient::connect_bound(model, local_address, &endpoints[..], "c").expect("client");
        assert_eq!(client.endpoint(), server_address);
        assert_eq!(
            client.get("/demo-data:config/count").expect("GET"),
            Some(Value::from(7))
        );
        assert_eq!(peer_receiver.recv().expect("peer"), local_address);
        server.join().expect("server");
    }

    #[test]
    fn public_client_fetch_uses_root_identifiers_and_preserves_methods() {
        use std::net::UdpSocket;
        use std::sync::mpsc;
        use std::thread;

        let server_socket = UdpSocket::bind("127.0.0.1:0").expect("server socket");
        let server_address = server_socket.local_addr().expect("server address");
        let (methods_sender, methods_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut service =
                GenericDataService::from_sid_contents(&[SID], DATA, "c").expect("service");
            let mut methods = Vec::new();
            let mut buffer = vec![0_u8; 65_535];
            for _ in 0..8 {
                let (length, peer) = server_socket.recv_from(&mut buffer).expect("request");
                let packet = Packet::from_bytes(&buffer[..length]).expect("request packet");
                if let MessageClass::Request(method) = packet.header.code {
                    methods.push(method);
                }
                let response = service
                    .handle_datagram(&buffer[..length])
                    .expect("service response");
                server_socket.send_to(&response, peer).expect("response");
            }
            methods_sender.send(methods).expect("methods");
        });

        let sid_contents = CompositeModel::from_sid_strings(&[SID]).expect("model");
        let mut client = DataClient::connect(sid_contents, server_address, "c").expect("client");
        assert!(client
            .discover(Some("d=0"))
            .expect("discovery")
            .contains("core.c.ds"));
        assert_eq!(
            client.get("/demo-data:config/count").expect("GET"),
            Some(Value::from(7))
        );
        assert_eq!(
            client.fetch("/demo-data:config/count").expect("FETCH"),
            Some(Value::from(7))
        );
        client
            .set("/demo-data:config/count", Value::from(30))
            .expect("SET");
        assert_eq!(
            client
                .fetch("/demo-data:config/count")
                .expect("updated FETCH"),
            Some(Value::from(30))
        );
        client.delete("/demo-data:config/name").expect("DELETE");
        assert_eq!(
            client.get("/demo-data:config/name").expect("deleted GET"),
            None
        );
        let snapshot = client.reload().expect("reload");
        assert_eq!(snapshot["demo-data:config"]["count"], Value::from(30));
        assert!(snapshot["demo-data:config"].get("name").is_none());
        server.join().expect("server");

        assert_eq!(
            methods_receiver.recv().expect("methods"),
            vec![
                RequestType::Get,
                RequestType::Get,
                RequestType::Fetch,
                RequestType::IPatch,
                RequestType::Fetch,
                RequestType::IPatch,
                RequestType::Get,
                RequestType::Get,
            ]
        );
    }
}
