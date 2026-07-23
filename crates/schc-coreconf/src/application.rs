//! Generic CORECONF application service and datagram client.
//!
//! The service owns a rustconf datastore and accepts one serialized CoAP
//! datagram at a time.
//! The client is a small UDP adapter that sends normal CoAP requests to the
//! core application endpoint.

use std::fs;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// The remote response did not correlate with the request.
    #[error("CoAP response did not correlate with request: {0}")]
    Correlation(String),
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
        response.header.code = MessageClass::Response(ResponseType::Content);
        response.set_token(request.get_token().to_vec());
        response.payload = format!(
            "</{management}>;rt=\"core.c.ds\";ct=112,</{streaming}>;rt=\"core.c.ev\";ct=141;obs"
        )
        .into_bytes();
        response.set_content_format(ContentFormat::TextPlain);
        response
    }
}

/// A normal CoAP UDP client for a device-owned CORECONF datastore.
///
/// rustconf owns discovery, GET, and mutation packet construction. The
/// separate socket and packet builder are intentionally limited to FETCH,
/// which the pinned public [`CoreconfClient`] trait does not expose.
pub struct DataClient {
    client: CoapLiteClient,
    fetch_socket: UdpSocket,
    endpoint: SocketAddr,
    resource_path: String,
    model: CompositeModel,
    next_fetch_message_id: u16,
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
        let endpoint = endpoint.to_socket_addrs()?.next().ok_or_else(|| {
            ApplicationError::Coap("endpoint resolved to no addresses".to_owned())
        })?;
        let resource_path = normalize_resource_path(&resource_path.into());
        let client = CoapLiteClient::connect(model.clone(), endpoint, resource_path.clone())?;
        let fetch_socket = UdpSocket::bind("0.0.0.0:0")?;
        fetch_socket.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
        fetch_socket.connect(endpoint)?;
        Ok(Self {
            client,
            fetch_socket,
            endpoint,
            resource_path,
            model,
            next_fetch_message_id: 1,
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

    /// Performs a remote CoAP GET and decodes its CORECONF value.
    ///
    /// A 4.04 response is represented as `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, decoding, or another response status.
    pub fn get(&mut self, path: &str) -> Result<Option<Value>, ApplicationError> {
        let path = canonical_path(path);
        self.client
            .fetch_path(&path)
            .map_err(ApplicationError::from)
    }

    /// Performs a remote CoAP FETCH and decodes its CORECONF value.
    ///
    /// This method emits the FETCH CoAP method code and does not alias GET.
    ///
    /// # Errors
    ///
    /// Returns an error for transport, decoding, or another response status.
    pub fn fetch(&mut self, path: &str) -> Result<Option<Value>, ApplicationError> {
        let path = canonical_path(path);
        let packet = self.new_fetch_packet(&path);
        let response = self.send_fetch(&packet)?;
        if matches!(
            response.header.code,
            MessageClass::Response(ResponseType::NotFound)
        ) {
            return Ok(None);
        }
        ensure_success(&response)?;
        let sid_value = coreconf_model::codec::cbor_to_json_value(&response.payload)?;
        self.model
            .sid_value_to_identifier_value_at_path(sid_value, &path)
            .map(Some)
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

    /// Sends an immediate CORECONF DELETE mutation for one path.
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

    fn new_fetch_packet(&mut self, path: &str) -> Packet {
        let mut packet = Packet::new();
        packet.header.message_id = self.next_fetch_message_id;
        self.next_fetch_message_id = self.next_fetch_message_id.wrapping_add(1);
        packet.header.code = MessageClass::Request(RequestType::Fetch);
        packet.header.set_type(MessageType::Confirmable);
        packet.set_token(vec![0xC0]);
        add_uri_path(&mut packet, &self.resource_path);
        if path != "/" {
            add_uri_path(&mut packet, path);
        }
        packet
    }

    fn send_fetch(&self, packet: &Packet) -> Result<Packet, ApplicationError> {
        let message_id = packet.header.message_id;
        let token = packet.get_token().to_vec();
        let bytes = packet
            .to_bytes()
            .map_err(|error| ApplicationError::Coap(error.to_string()))?;
        self.fetch_socket.send(&bytes)?;
        let mut buffer = vec![0_u8; 65_535];
        let length = self.fetch_socket.recv(&mut buffer)?;
        let response = Packet::from_bytes(&buffer[..length])
            .map_err(|error| ApplicationError::Coap(error.to_string()))?;
        if response.header.message_id != message_id {
            return Err(ApplicationError::Correlation(format!(
                "message ID {}, received {}",
                message_id, response.header.message_id
            )));
        }
        if response.get_token() != token.as_slice() {
            return Err(ApplicationError::Correlation("token mismatch".to_owned()));
        }
        Ok(response)
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
        .filter(|(identifier, _)| filter.map_or(true, |filter| identifier.contains(filter)))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
        .into_iter()
        .map(|(identifier, sid)| format!("{identifier} (sid {sid})"))
        .collect()
}

fn ensure_success(packet: &Packet) -> Result<(), ApplicationError> {
    match packet.header.code {
        MessageClass::Response(code) if !code.is_error() => Ok(()),
        code => Err(ApplicationError::Remote {
            code: code.to_string(),
            message: String::from_utf8_lossy(&packet.payload).into_owned(),
        }),
    }
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

    #[test]
    fn discovery_and_fetch_preserve_coap_correlation() {
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
        assert!(matches!(
            response.header.code,
            MessageClass::Response(ResponseType::Content)
        ));
    }

    #[test]
    fn client_performs_distinct_remote_methods_and_immediate_mutations() {
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
                RequestType::Delete,
                RequestType::Get,
                RequestType::Get,
            ]
        );
    }
}
