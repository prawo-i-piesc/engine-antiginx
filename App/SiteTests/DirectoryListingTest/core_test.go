package DirectoryListingTest

import "testing"

func TestProbesIncludeTargetDirectories(t *testing.T) {
	list := probes("/blog/2026/post.html")

	found := map[string]bool{}
	for _, probe := range list {
		if found[probe.Path] {
			t.Errorf("%s probed twice", probe.Path)
		}
		found[probe.Path] = true
	}
	for _, want := range []string{"/", "/uploads/", "/blog/", "/blog/2026/"} {
		if !found[want] {
			t.Errorf("%s not probed", want)
		}
	}
	if len(list) != len(commonDirectories)+len(sensitiveDirectories)+2 {
		t.Errorf("got %d probes, want the dataset plus 2 target directories", len(list))
	}
}

func TestProbesForRootTarget(t *testing.T) {
	for _, target := range []string{"", "/", "/index.html"} {
		if got := len(probes(target)); got != len(commonDirectories)+len(sensitiveDirectories) {
			t.Errorf("target %q: got %d probes, want only the dataset", target, got)
		}
	}
}

// Listing pages as each server generates them, trimmed to the parts the signatures read.
func TestListingSignatures(t *testing.T) {
	cases := map[string]string{
		"<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href=\"/\">Parent Directory</a><address>Proudly Served by LiteSpeed Web Server</address></body></html>":                         "LiteSpeed",
		"<html><head><title>Index of /</title></head><body><h1>Index of /</h1><a href=\"../\">../</a><address>Node.js v20 / <a href=\"https://github.com/http-party/http-server\">http-server</a></address></body></html>": "Node http-server",
		"<HTML><HEAD><TITLE>Index of /</TITLE></HEAD><BODY><H1>Index of /</H1><A HREF=\"..\">Parent Directory</A><ADDRESS>WEBrick/1.8.1 (Ruby/3.3.0)</ADDRESS></BODY></HTML>":                                              "WEBrick",
		"<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href=\"/\">Parent Directory</a></body></html>":                                                                              "Apache",
		"<!DOCTYPE html><html><head><title>listing directory /</title></head><body><ul id=\"files\"><li><a href=\"/a.txt\">a.txt</a></li></ul></body></html>":                                                              "Express serve-index",
		"<html><head><title>/backup/</title></head><body><table></table><footer>Served with <a rel=\"noopener noreferrer\" href=\"https://caddyserver.com\">Caddy</a></footer></body></html>":                              "Caddy",
		"<!doctype html>\n<meta name=\"viewport\" content=\"width=device-width\">\n<pre>\n<a href=\"logs/\">logs/</a>\n</pre>\n":                                                                                           "Go http.FileServer",
		"<!DOCTYPE html><html><head><title>Deno File Server</title></head><body><main><h1>Index of /</h1></main></body></html>":                                                                                            "Deno file_server",
		"<html><head><title>index - powered by h5ai v0.30.0</title></head><body></body></html>":                                                                                                                            "h5ai",
	}
	for body, want := range cases {
		if server, ok := scanner.Detect(body); !ok || server != want {
			t.Errorf("listing for %s detected as %q (%v)", want, server, ok)
		}
	}

	for _, page := range []string{
		"<html><head><title>Welcome</title></head><body><h1>Index of our products</h1></body></html>",
		"<!doctype html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body><pre>code</pre></body></html>",
		"<html><body><p>This site is served with love. Built on caddyserver.com docs.</p></body></html>",
	} {
		if server, ok := scanner.Detect(page); ok {
			t.Errorf("ordinary page detected as a %s listing", server)
		}
	}
}
