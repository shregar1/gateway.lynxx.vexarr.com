//! Encoding algorithms — HTML/JSON escaping, compression, URI normalization,
//! content negotiation, ETag generation, path manipulation, probabilistic sets,
//! and Vary key encoding.

pub mod escape_html;
pub mod escape_json;
pub mod slz_compress;
pub mod uri_normalize;
pub mod accept_encoding;
pub mod etag_encode;
pub mod path_trim;
pub mod golomb_set;
pub mod vary_encode;
