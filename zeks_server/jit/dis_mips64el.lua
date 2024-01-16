----------------------------------------------------------------------------
-- LuaJIT MIPS64EL disassembler wrapper module.
--
-- Copyright (C) 2005-2017 Mike Pall. All rights reserved.
-- Released under the MIT license. See Copyright Notice in luajit.h
----------------------------------------------------------------------------
-- This module just exports the little-endian functions from the
-- MIPS disassembler module. All the interesting stuff is there.
------------------------------------------------------------------------------

local dis_mips = require((string.match(..., ".*%.") or "").."dis_mips")
return {
  create = dis_mips.create_el,
  disass = dis_mips.disass_el,
  regname = dis_mips.regname
}

