# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Binary Logging Infrastructure (BLOG)
#

obj-$(CONFIG_BLOG) += blog.o

blog-y := blog_core.o blog_batch.o blog_pagefrag.o blog_des.o blog_module.o

# Debug support
# blog-$(CONFIG_BLOG_DEBUG) += blog_debug.o

# Compiler flags
ccflags-$(CONFIG_BLOG_DEBUG) += -DBLOG_DEBUG=1
ccflags-$(CONFIG_BLOG_TRACK_USAGE) += -DBLOG_TRACK_USAGE=1
