# -*- coding: utf-8 -*-
# Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Defines a build related helper class."""

from __future__ import print_function

import os
import sys


class BuildObject(object):
  """Common base class that defines key paths in the source tree.

  Classes that inherit from BuildObject can access scripts in the src/scripts
  directory, and have a handle to the static directory of the devserver.
  """
  def __init__(self, static_dir):
    self.devserver_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    self.static_dir = static_dir

  def GetDefaultBoardID(self):
    """Returns the default board id stored in .default_board.

    Default to x86-generic, if that isn't set.
    """
    #TODO
    return "beaglebone"