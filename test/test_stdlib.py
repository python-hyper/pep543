# -*- coding: utf-8 -*-
"""
Tests for the standard library PEP 543 shim.
"""
import pep543.stdlib

from .backend_tests import SimpleNegotiation


class TestSimpleNegotiationStdlib(SimpleNegotiation):
    BACKEND = pep543.stdlib.STDLIB_BACKEND
