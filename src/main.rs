use uuid::Uuid;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::str;
use serde::Deserialize;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use rsa::BigUint;
use base64::{encode, decode};

const IP: &str = "192.168.100.20";
const PORT: u32 = 8080;

struct ServerData
{
    stream: TcpStream
}

fn open_connection() -> Option<ServerData>
{
    let mut address = String::new();
    address += IP;
    address += ":";
    address += &PORT.to_string();
    match TcpStream::connect(address)
    {
        Ok(stream) => 
        {
            let data = ServerData { stream };
            println!("Successfully connected to server {}:{}", IP, PORT);
            Some(data)
        },
        Err(e) => 
        {
            println!("Failed to connect: {}", e);
            None
        }
    }
}

fn send_request(server: &mut ServerData, query: String)
{
    let _ = server.stream.write(query.as_bytes());
}

fn get_request_result(server: &mut ServerData) -> Option<String>
{
    let mut buf: Vec<u8> = Vec::new();
    let _ = server.stream.read_to_end(&mut buf);
    let s = str::from_utf8(&buf)
        .unwrap_or_else(|_| "ERROR");

    if s == "ERROR"
    {
        return None;
    }

    Some(s.to_string())
}

#[derive(Debug)]
struct ConnectionInfo
{
    connection_id: Uuid,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct ConnectionJSON
{
    connection_id: String,
    exponent: String,
    modulus: String,
    result: bool,
    message: String,
}

fn append_headers(msg: &mut String) {
    *msg += " HTTP/1.1\r\nHost: ";
    *msg += IP;
    *msg += ":";
    *msg += &PORT.to_string();
    *msg += "\r\n\r\n";
}

fn make_connection(server: &mut ServerData, client_id: Uuid) -> Option<ConnectionInfo>
{
    let mut msg = String::new();
    msg += "GET /?type=connect&clientID=";
    msg += &client_id.to_string();
    append_headers(&mut msg);
    send_request(server, msg);

    let res = get_request_result(server);
    if res == None
    {
        return None;
    }

    let s = res.unwrap();

    let index = s.find("{").unwrap();
    let json_s = &s[index..];
    let json: ConnectionJSON = serde_json::from_str(&json_s).expect("Bad JSON");
    let conn_id = Uuid::parse_str(&json.connection_id).unwrap();
    let modulus = json.modulus;
    let exponent = json.exponent;

    let mod_bytes = decode(modulus).expect("ERROR");
    let exp_bytes = decode(exponent).expect("ERROR");

    let conn_info = ConnectionInfo { connection_id: conn_id, modulus: mod_bytes, exponent: exp_bytes };
    Some(conn_info)
}

fn close_connection(server: &mut ServerData, connection_id: Uuid) -> bool
{
    let mut msg = String::new();
    msg += "GET /?type=disconnect&connection_id=";
    msg += &connection_id.to_string();
    append_headers(&mut msg);
    send_request(server, msg);

    let res = get_request_result(server);
    if res == None
    {
        return false;
    }

    true
}

fn login(server: &mut ServerData, connection_id: Uuid, username: &str, pass_encrypted: &str) -> bool
{
    let mut msg = String::new();
    msg += "GET /?type=login&connection_id=";
    msg += &connection_id.to_string();
    msg += "&username=";
    msg += username;
    msg += "&password=";
    msg += pass_encrypted;
    append_headers(&mut msg);
    send_request(server, msg);
    let _ = server.stream.flush();

    let res = get_request_result(server);
    if res == None
    {
        return false;
    }

    println!("{:?}", res);
    let s = res.unwrap();
    println!("{}", s);
    true
}

fn main()
{
    let client_id = Uuid::new_v4();
    println!("Client ID is {:?}", client_id);

    let mut server = open_connection().unwrap();
    let data = make_connection(&mut server, client_id).unwrap();

    let n: BigUint = BigUint::from_bytes_be(&data.modulus[..]);
    let e: BigUint = BigUint::from_bytes_be(&data.exponent[..]);
    let mut rng = rand::thread_rng();
    let pub_key = RsaPublicKey::new(n, e).unwrap();

    let user = "test";
    let pass = b"password";
    let pass_enc = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &pass[..]).unwrap();
    let pass_encrypted = encode(pass_enc);
    let res = login(&mut server, data.connection_id, user, &pass_encrypted);
    println!("Result: {}", res);

    close_connection(&mut server, data.connection_id);
}
