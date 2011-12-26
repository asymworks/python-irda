#!/usr/bin/env python2
from distutils.core import setup, Extension

module1 = Extension('irda', sources = ['src/irda.c', 'src/module.c'])

setup(name = 'irda',
	version = '1.1',
	description = 'IrDA socket interface for Python',
	ext_modules = [module1])
