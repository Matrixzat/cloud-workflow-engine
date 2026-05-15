// Runtime URL reconstruction — prevents static string analysis of libapp.so.
// URLs are never stored as string literals; they are reconstructed from
// integer arrays at runtime so they cannot be found by strings / Blutter / dex2jar.
String _u(List<int> c) => String.fromCharCodes(c);
