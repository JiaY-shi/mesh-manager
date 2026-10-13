// SPDX-License-Identifier: GPL-2.0-only
// CommonJS entry loaded only when enrollment is enabled; exported modules stay ES modules.
'use strict';
import { enrollment_tick } from './advanced.uc';
return enrollment_tick;
