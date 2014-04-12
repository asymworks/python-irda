#!/usr/bin/env python2
from distutils.core import setup, Extension
import platform

libraries = []
if platform.system() == 'Windows':
	libraries = ['ws2_32']

module1 = Extension('irda', sources = ['src/irda.c', 'src/module.c'], libraries=libraries)

setup(name = 'irda',
	version = '1.1',
	description = 'IrDA socket interface for Python',
	ext_modules = [module1])
