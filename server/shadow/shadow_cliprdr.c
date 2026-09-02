/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Minimal shadow-server clipboard file-transfer test harness.
 *
 * server/shadow never wired up a CliprdrServerContext at all: the channel gets
 * joined at the MCS level but nothing ever processes CB_* PDUs on it. This is
 * not a fix for that (real clipboard sharing needs X11 selection integration,
 * capability UX, bidirectional sync - a much bigger feature). It only exists
 * to complete a real wire round-trip for testing: whenever a client
 * advertises FileGroupDescriptorW, pull the descriptor list and file contents
 * and write them under SHADOW_CLIPRDR_OUTDIR (default ./shadow-cliprdr-out).
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

#include <freerdp/config.h>

#include <stdio.h>

#include <winpr/crt.h>
#include <winpr/assert.h>
#include <winpr/file.h>
#include <winpr/path.h>
#include <winpr/shell.h>
#include <winpr/wlog.h>

#include <freerdp/channels/cliprdr.h>
#include <freerdp/utils/cliprdr_utils.h>
#include <freerdp/log.h>

#include "shadow.h"
#include "shadow_cliprdr.h"

#define TAG SERVER_TAG("shadow.cliprdr")
#define SHADOW_CLIPRDR_PATH_MAX 4096

typedef struct
{
	CliprdrServerContext* context;
	char outDir[SHADOW_CLIPRDR_PATH_MAX];
	FILEDESCRIPTORW* descriptors;
	UINT32 count;
	UINT32 index;
	UINT64 offset;
	FILE* current;
	UINT32 streamId;
	UINT32 filesWritten;
	UINT64 bytesWritten;
} SHADOW_CLIPRDR_FETCH;

static void shadow_cliprdr_fetch_reset(SHADOW_CLIPRDR_FETCH* fetch)
{
	if (fetch->current)
	{
		fclose(fetch->current);
		fetch->current = NULL;
	}
	free(fetch->descriptors);
	fetch->descriptors = NULL;
	fetch->count = 0;
	fetch->index = 0;
	fetch->offset = 0;
}

/* Rejects absolute paths and ".." components so a malicious peer can't write
 * outside outDir. Converts the wire's backslash separators to '/' in place. */
static BOOL shadow_cliprdr_safe_relative_path(char* path)
{
	if (!path || !path[0] || path[0] == '/' || path[0] == '\\')
		return FALSE;

	for (char* p = path; *p; p++)
	{
		if (*p == '\\')
			*p = '/';
	}

	const char* comp = path;
	while (TRUE)
	{
		const char* end = strchr(comp, '/');
		const size_t len = end ? (size_t)(end - comp) : strlen(comp);
		if ((len == 2) && (comp[0] == '.') && (comp[1] == '.'))
			return FALSE;
		if (!end)
			break;
		comp = end + 1;
	}
	return TRUE;
}

static void shadow_cliprdr_mkpath(const char* path)
{
	char buffer[SHADOW_CLIPRDR_PATH_MAX];
	const size_t len = strnlen(path, sizeof(buffer) - 1);
	memcpy(buffer, path, len);
	buffer[len] = '\0';

	for (size_t i = 1; i < len; i++)
	{
		if (buffer[i] == '/')
		{
			buffer[i] = '\0';
			(void)CreateDirectoryA(buffer, NULL);
			buffer[i] = '/';
		}
	}
	(void)CreateDirectoryA(buffer, NULL);
}

static UINT shadow_cliprdr_request_chunk(SHADOW_CLIPRDR_FETCH* fetch)
{
	const FILEDESCRIPTORW* fd = &fetch->descriptors[fetch->index];
	const UINT64 size = (((UINT64)fd->nFileSizeHigh) << 32) | fd->nFileSizeLow;
	const UINT64 remaining = size - fetch->offset;
	const UINT32 chunk = (UINT32)MIN(remaining, 4ULL * 1024 * 1024);

	CLIPRDR_FILE_CONTENTS_REQUEST request = { 0 };
	request.common.msgType = CB_FILECONTENTS_REQUEST;
	request.streamId = ++fetch->streamId;
	request.listIndex = fetch->index;
	request.dwFlags = FILECONTENTS_RANGE;
	request.nPositionLow = (UINT32)(fetch->offset & 0xFFFFFFFFu);
	request.nPositionHigh = (UINT32)(fetch->offset >> 32);
	request.cbRequested = chunk;
	request.haveClipDataId = FALSE;
	return fetch->context->ServerFileContentsRequest(fetch->context, &request);
}

/* Skips directory entries (just mkdir's them) until it finds a file to pull, or
 * finishes and logs a summary. */
static UINT shadow_cliprdr_advance(SHADOW_CLIPRDR_FETCH* fetch)
{
	while (fetch->index < fetch->count)
	{
		FILEDESCRIPTORW* fd = &fetch->descriptors[fetch->index];
		char name[SHADOW_CLIPRDR_PATH_MAX] = { 0 };
		if (ConvertWCharNToUtf8(fd->cFileName, ARRAYSIZE(fd->cFileName), name, sizeof(name)) < 0)
		{
			WLog_ERR(TAG, "failed to convert file name, aborting fetch");
			shadow_cliprdr_fetch_reset(fetch);
			return CHANNEL_RC_OK;
		}

		if (!shadow_cliprdr_safe_relative_path(name))
		{
			WLog_ERR(TAG, "rejecting unsafe path '%s', aborting fetch", name);
			shadow_cliprdr_fetch_reset(fetch);
			return CHANNEL_RC_OK;
		}

		char localPath[SHADOW_CLIPRDR_PATH_MAX];
		(void)_snprintf(localPath, sizeof(localPath), "%s/%s", fetch->outDir, name);

		const BOOL isDir =
		    (fd->dwFlags & FD_ATTRIBUTES) && (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
		if (isDir)
		{
			shadow_cliprdr_mkpath(localPath);
			fetch->index++;
			continue;
		}

		char* slash = strrchr(localPath, '/');
		if (slash)
		{
			*slash = '\0';
			shadow_cliprdr_mkpath(localPath);
			*slash = '/';
		}

		const UINT64 size = (((UINT64)fd->nFileSizeHigh) << 32) | fd->nFileSizeLow;
		fetch->current = fopen(localPath, "wb");
		if (!fetch->current)
		{
			WLog_ERR(TAG, "failed to open '%s' for writing", localPath);
			shadow_cliprdr_fetch_reset(fetch);
			return CHANNEL_RC_OK;
		}
		fetch->offset = 0;
		fetch->filesWritten++;

		if (size == 0)
		{
			fclose(fetch->current);
			fetch->current = NULL;
			fetch->index++;
			continue;
		}

		WLog_INFO(TAG, "pulling '%s' (%" PRIu64 " bytes)", localPath, size);
		return shadow_cliprdr_request_chunk(fetch);
	}

	WLog_INFO(TAG, "clipboard fetch complete: %" PRIu32 " files, %" PRIu64 " bytes", fetch->filesWritten,
	          fetch->bytesWritten);
	shadow_cliprdr_fetch_reset(fetch);
	return CHANNEL_RC_OK;
}

static UINT shadow_cliprdr_on_client_format_list(CliprdrServerContext* context,
                                                 const CLIPRDR_FORMAT_LIST* formatList)
{
	SHADOW_CLIPRDR_FETCH* fetch = (SHADOW_CLIPRDR_FETCH*)context->custom;
	UINT32 fileFormatId = 0;

	for (UINT32 i = 0; i < formatList->numFormats; i++)
	{
		const CLIPRDR_FORMAT* format = &formatList->formats[i];
		if (format->formatName && (strcmp(format->formatName, "FileGroupDescriptorW") == 0))
			fileFormatId = format->formatId;
	}

	CLIPRDR_FORMAT_LIST_RESPONSE response = { 0 };
	response.common.msgType = CB_FORMAT_LIST_RESPONSE;
	response.common.msgFlags = CB_RESPONSE_OK;
	UINT error = context->ServerFormatListResponse(context, &response);
	if (error != CHANNEL_RC_OK)
		return error;

	if (fileFormatId == 0)
		return CHANNEL_RC_OK;

	WLog_INFO(TAG, "client advertised FileGroupDescriptorW (id=0x%08" PRIX32 "), requesting it",
	          fileFormatId);

	CLIPRDR_FORMAT_DATA_REQUEST request = { 0 };
	request.common.msgType = CB_FORMAT_DATA_REQUEST;
	request.requestedFormatId = fileFormatId;
	return context->ServerFormatDataRequest(context, &request);
}

static UINT
shadow_cliprdr_on_client_format_data_response(CliprdrServerContext* context,
                                              const CLIPRDR_FORMAT_DATA_RESPONSE* formatDataResponse)
{
	SHADOW_CLIPRDR_FETCH* fetch = (SHADOW_CLIPRDR_FETCH*)context->custom;

	if (!(formatDataResponse->common.msgFlags & CB_RESPONSE_OK))
	{
		WLog_ERR(TAG, "client failed to provide FileGroupDescriptorW");
		return CHANNEL_RC_OK;
	}

	shadow_cliprdr_fetch_reset(fetch);
	if (cliprdr_parse_file_list(formatDataResponse->requestedFormatData, formatDataResponse->common.dataLen,
	                            &fetch->descriptors, &fetch->count) != CHANNEL_RC_OK ||
	    fetch->count == 0)
	{
		WLog_ERR(TAG, "failed to parse file descriptor list");
		return CHANNEL_RC_OK;
	}

	WLog_INFO(TAG, "received descriptor list: %" PRIu32 " entries", fetch->count);
	return shadow_cliprdr_advance(fetch);
}

static UINT shadow_cliprdr_on_client_file_contents_response(
    CliprdrServerContext* context, const CLIPRDR_FILE_CONTENTS_RESPONSE* fileContentsResponse)
{
	SHADOW_CLIPRDR_FETCH* fetch = (SHADOW_CLIPRDR_FETCH*)context->custom;

	if (!fetch->current || (fileContentsResponse->streamId != fetch->streamId))
		return CHANNEL_RC_OK;

	if (!(fileContentsResponse->common.msgFlags & CB_RESPONSE_OK))
	{
		WLog_ERR(TAG, "client failed a file contents request, aborting fetch");
		shadow_cliprdr_fetch_reset(fetch);
		return CHANNEL_RC_OK;
	}

	const UINT32 received = fileContentsResponse->cbRequested;
	if ((received > 0) && fileContentsResponse->requestedData)
	{
		if (fwrite(fileContentsResponse->requestedData, 1, received, fetch->current) != received)
		{
			WLog_ERR(TAG, "short write, aborting fetch");
			shadow_cliprdr_fetch_reset(fetch);
			return CHANNEL_RC_OK;
		}
		fetch->offset += received;
		fetch->bytesWritten += received;
	}

	const FILEDESCRIPTORW* fd = &fetch->descriptors[fetch->index];
	const UINT64 size = (((UINT64)fd->nFileSizeHigh) << 32) | fd->nFileSizeLow;
	if ((fetch->offset >= size) || (received == 0))
	{
		fclose(fetch->current);
		fetch->current = NULL;
		fetch->index++;
		return shadow_cliprdr_advance(fetch);
	}
	return shadow_cliprdr_request_chunk(fetch);
}

BOOL shadow_client_cliprdr_init(rdpShadowClient* client)
{
	WINPR_ASSERT(client);

	const BOOL joined = WTSVirtualChannelManagerIsChannelJoined(client->vcm, CLIPRDR_SVC_CHANNEL_NAME);
	WLog_INFO(TAG, "cliprdr channel joined-check: %d", joined);
	if (!joined)
		return TRUE;

	SHADOW_CLIPRDR_FETCH* fetch = calloc(1, sizeof(SHADOW_CLIPRDR_FETCH));
	if (!fetch)
		return FALSE;

	const char* outDirEnv = getenv("SHADOW_CLIPRDR_OUTDIR");
	(void)_snprintf(fetch->outDir, sizeof(fetch->outDir), "%s",
	                outDirEnv ? outDirEnv : "shadow-cliprdr-out");
	shadow_cliprdr_mkpath(fetch->outDir);

	CliprdrServerContext* cliprdr = client->cliprdr = cliprdr_server_context_new(client->vcm);
	if (!cliprdr)
	{
		free(fetch);
		return FALSE;
	}

	fetch->context = cliprdr;
	cliprdr->custom = fetch;
	cliprdr->rdpcontext = (rdpContext*)client;
	/* capability flags are server-implementation policy, not a channel default:
	 * narrowed by negotiation, never turned on by the channel itself. */
	cliprdr->useLongFormatNames = TRUE;
	cliprdr->streamFileClipEnabled = TRUE;
	cliprdr->ClientFormatList = shadow_cliprdr_on_client_format_list;
	cliprdr->ClientFormatDataResponse = shadow_cliprdr_on_client_format_data_response;
	cliprdr->ClientFileContentsResponse = shadow_cliprdr_on_client_file_contents_response;

	const UINT error = cliprdr->Start(cliprdr);
	if (error != CHANNEL_RC_OK)
	{
		WLog_ERR(TAG, "cliprdr Start failed with error %" PRIu32, error);
		cliprdr_server_context_free(cliprdr);
		client->cliprdr = NULL;
		free(fetch);
		return FALSE;
	}

	WLog_INFO(TAG, "clipboard file-transfer test harness active, writing to '%s'", fetch->outDir);
	return TRUE;
}

void shadow_client_cliprdr_uninit(rdpShadowClient* client)
{
	WINPR_ASSERT(client);
	if (client->cliprdr)
	{
		SHADOW_CLIPRDR_FETCH* fetch = (SHADOW_CLIPRDR_FETCH*)client->cliprdr->custom;
		client->cliprdr->Stop(client->cliprdr);
		cliprdr_server_context_free(client->cliprdr);
		client->cliprdr = NULL;
		if (fetch)
		{
			shadow_cliprdr_fetch_reset(fetch);
			free(fetch);
		}
	}
}
