/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef CONFIG_COMMAND_LINE_H
#define CONFIG_COMMAND_LINE_H

#include "config/data.h"

namespace config
{

Data parse_command_line(int argc, char* argv[]);

} // namepsace config

#endif //CONFIG_COMMAND_LINE_H
