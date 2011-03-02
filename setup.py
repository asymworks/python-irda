#!/usr/bin/env python2
from distutils.core import setup, Extension

module1 = Extension('irsocket', sources = ['irsocket.c'])

setup(name = 'irsocket',
	version = '1.0',
	description = 'IrDA socket interface for Python',
	ext_modules = [module1])
