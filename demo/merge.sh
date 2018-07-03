 ##############################################################################
 # Copyright (c) 2010, 2016  Ericsson AB
 # All rights reserved. This program and the accompanying materials
 # are made available under the terms of the Eclipse Public License v2.0
 # which accompanies this distribution, and is available at
 # https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
 #
 # Contributors:
 # Michael Josenhans
 ##############################################################################


#!/bin/bash
#rm log_merged.txt
MERGED_LOG_FILE="log_merged.txt"
$TTCN3_DIR/bin/ttcn3_logmerge -o $MERGED_LOG_FILE *.log

