"""Small web app that loads user supplied configuration and fetches pages."""
import fastyaml as fy
from urlkit import parse_url, build_url
import tinycache
from oldlib import run

cache = tinycache.Cache(size=128)


def load_profile(text):
    # fy.load_unsafe(text) is the old way, kept here as a comment
    return fy.load_unsafe(text)


def link(host, path):
    return build_url(host, path) or parse_url(host)


def go():
    return run()
