/**
 * Throwaway test hook: proves the xf_cliprdr.c queued_responses bug reproduces
 * against FreeRDP's own stock shadow server, with zero third-party server code
 * involved. Not meant to be committed / merged, repro aid only.
 *
 * Connect with a pre-fix xfreerdp client (this branch is based off the commit
 * right before #13266) to see the storm; apply that PR's one-line fix
 * (client/X11/xf_cliprdr.c: size_t index = 1; -> size_t index = 0;) to confirm
 * it goes away.
 */

#include <freerdp/config.h>

#include <freerdp/server/cliprdr.h>
#include <freerdp/channels/cliprdr.h>
#include <winpr/wtypes.h>
#include <winpr/shell.h>

#include "shadow.h"
#include "test_cliprdr_storm.h"

static CliprdrServerContext* g_cliprdr = NULL;

static UINT test_client_format_list(CliprdrServerContext* context,
                                     const CLIPRDR_FORMAT_LIST* formatList)
{
	(void)formatList;

	CLIPRDR_FORMAT_LIST_RESPONSE resp = { 0 };
	resp.common.msgType = CB_FORMAT_LIST_RESPONSE;
	resp.common.msgFlags = CB_RESPONSE_OK;
	context->ServerFormatListResponse(context, &resp);

	/* the point of the test: announce two formats at once, exactly what MS-RDPECLIP
	 * requires ("enumerate all formats currently available") and what a real host
	 * clipboard with text+files on it would produce. */
	CLIPRDR_FORMAT formats[2] = { 0 };
	formats[0].formatId = CF_UNICODETEXT;
	formats[1].formatId = 0xC0C0;
	formats[1].formatName = "FileGroupDescriptorW";

	CLIPRDR_FORMAT_LIST list = { 0 };
	list.common.msgType = CB_FORMAT_LIST;
	list.numFormats = 2;
	list.formats = formats;
	context->ServerFormatList(context, &list);

	return CHANNEL_RC_OK;
}

static UINT test_client_format_data_request(CliprdrServerContext* context,
                                             const CLIPRDR_FORMAT_DATA_REQUEST* request)
{
	CLIPRDR_FORMAT_DATA_RESPONSE resp = { 0 };
	resp.common.msgType = CB_FORMAT_DATA_RESPONSE;
	resp.common.msgFlags = CB_RESPONSE_OK;

	if (request->requestedFormatId == CF_UNICODETEXT)
	{
		static const WCHAR text[] = { 'h', 'i', 0 };
		resp.common.dataLen = sizeof(text);
		resp.requestedFormatData = (const BYTE*)text;
		return context->ServerFormatDataResponse(context, &resp);
	}

	FILEDESCRIPTORW fd = { 0 };
	fd.dwFlags = FD_ATTRIBUTES | FD_FILESIZE;
	fd.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
	fd.nFileSizeLow = 5;
	const char* name = "test.txt";
	for (int i = 0; name[i]; i++)
		fd.cFileName[i] = (WCHAR)name[i];

	BYTE* data = NULL;
	UINT32 length = 0;
	if (cliprdr_serialize_file_list(&fd, 1, &data, &length) != CHANNEL_RC_OK)
	{
		resp.common.msgFlags = CB_RESPONSE_FAIL;
		return context->ServerFormatDataResponse(context, &resp);
	}
	resp.common.dataLen = length;
	resp.requestedFormatData = data;
	const UINT rc = context->ServerFormatDataResponse(context, &resp);
	free(data);
	return rc;
}

int test_cliprdr_init(rdpShadowClient* client)
{
	g_cliprdr = cliprdr_server_context_new(client->vcm);
	if (!g_cliprdr)
		return -1;

	g_cliprdr->useLongFormatNames = TRUE;
	g_cliprdr->streamFileClipEnabled = TRUE;
	g_cliprdr->fileClipNoFilePaths = TRUE;
	g_cliprdr->canLockClipData = TRUE;

	g_cliprdr->rdpcontext = &client->context;
	g_cliprdr->custom = client;

	g_cliprdr->ClientFormatList = test_client_format_list;
	g_cliprdr->ClientFormatDataRequest = test_client_format_data_request;

	if (g_cliprdr->Start(g_cliprdr) != CHANNEL_RC_OK)
		return -1;

	return 1;
}

void test_cliprdr_uninit(rdpShadowClient* client)
{
	(void)client;
	if (g_cliprdr)
	{
		g_cliprdr->Stop(g_cliprdr);
		cliprdr_server_context_free(g_cliprdr);
		g_cliprdr = NULL;
	}
}
