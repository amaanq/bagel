use std::{
   io::{
      BufRead as _,
      BufReader,
      Write as _,
   },
   net::{
      TcpStream,
      ToSocketAddrs as _,
   },
   time::Duration,
};

/// Query RADB/WHOIS for routes announced by an ASN.
/// Returns a list of IP prefix strings (e.g. "192.0.2.0/24").
pub fn query_asn_routes(asn: u32) -> bagel_core::Result<Vec<String>> {
   let server = "whois.radb.net:43";
   let query = format!("-i origin AS{asn}\r\n");

   let addr = server
      .to_socket_addrs()?
      .next()
      .ok_or_else(|| bagel_core::Error::Other(format!("{server} did not resolve").into()))?;
   let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
   stream.set_read_timeout(Some(Duration::from_secs(10)))?;
   stream.write_all(query.as_bytes())?;

   let reader = BufReader::new(stream);
   let mut prefixes = Vec::new();

   for line in reader.lines() {
      let line = line?;
      if let Some(prefix) = line.strip_prefix("route:") {
         prefixes.push(prefix.trim().to_owned());
      } else if let Some(prefix) = line.strip_prefix("route6:") {
         prefixes.push(prefix.trim().to_owned());
      }
   }

   Ok(prefixes)
}
