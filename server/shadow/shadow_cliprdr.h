/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Minimal shadow-server clipboard file-transfer test harness.
 *
 * Not a real clipboard-sharing implementation: no X11 selection integration,
 * no bidirectional sync. On every client format list that advertises
 * FileGroupDescriptorW, it auto-pulls the descriptor list and file contents
 * and writes them to disk, purely to exercise the wire protocol end to end.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_SERVER_SHADOW_CLIPRDR_H
#define FREERDP_SERVER_SHADOW_CLIPRDR_H

#include <freerdp/server/shadow.h>

#ifdef __cplusplus
extern "C"
{
#endif

	WINPR_ATTR_NODISCARD BOOL shadow_client_cliprdr_init(rdpShadowClient* client);
	void shadow_client_cliprdr_uninit(rdpShadowClient* client);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_SHADOW_CLIPRDR_H */
