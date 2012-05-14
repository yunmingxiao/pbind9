/*
 * Generated by convertxsl.pl 1.14 2008/07/17 23:43:26 jinmei Exp  
 * From bind9.xsl 1.21 2009/01/27 23:47:54 tbox Exp 
 */
static char xslmsg[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	"<!--\n"
	" - Copyright (C) 2006-2009 Internet Systems Consortium, Inc. (\"ISC\")\n"
	" -\n"
	" - Permission to use, copy, modify, and/or distribute this software for any\n"
	" - purpose with or without fee is hereby granted, provided that the above\n"
	" - copyright notice and this permission notice appear in all copies.\n"
	" -\n"
	" - THE SOFTWARE IS PROVIDED \"AS IS\" AND ISC DISCLAIMS ALL WARRANTIES WITH\n"
	" - REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY\n"
	" - AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,\n"
	" - INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM\n"
	" - LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE\n"
	" - OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR\n"
	" - PERFORMANCE OF THIS SOFTWARE.\n"
	"-->\n"
	"\n"
	"<!-- \045Id: bind9.xsl,v 1.21 2009/01/27 23:47:54 tbox Exp \045 -->\n"
	"\n"
	"<xsl:stylesheet version=\"1.0\"\n"
	" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\n"
	" xmlns=\"http://www.w3.org/1999/xhtml\">\n"
	" <xsl:template match=\"isc/bind/statistics\">\n"
	" <html>\n"
	" <head>\n"
	" <style type=\"text/css\">\n"
	"body {\n"
	" font-family: sans-serif;\n"
	" background-color: #ffffff;\n"
	" color: #000000;\n"
	"}\n"
	"\n"
	"table {\n"
	" border-collapse: collapse;\n"
	"}\n"
	"\n"
	"tr.rowh {\n"
	" text-align: center;\n"
	" border: 1px solid #000000;\n"
	" background-color: #8080ff;\n"
	" color: #ffffff;\n"
	"}\n"
	"\n"
	"tr.row {\n"
	" text-align: right;\n"
	" border: 1px solid #000000;\n"
	" background-color: teal;\n"
	" color: #ffffff;\n"
	"}\n"
	"\n"
	"tr.lrow {\n"
	" text-align: left;\n"
	" border: 1px solid #000000;\n"
	" background-color: teal;\n"
	" color: #ffffff;\n"
	"}\n"
	"\n"
	"td, th {\n"
	" padding-right: 5px;\n"
	" padding-left: 5px;\n"
	"}\n"
	"\n"
	".header h1 {\n"
	" background-color: teal;\n"
	" color: #ffffff;\n"
	" padding: 4px;\n"
	"}\n"
	"\n"
	".content {\n"
	" background-color: #ffffff;\n"
	" color: #000000;\n"
	" padding: 4px;\n"
	"}\n"
	"\n"
	".item {\n"
	" padding: 4px;\n"
	" align: right;\n"
	"}\n"
	"\n"
	".value {\n"
	" padding: 4px;\n"
	" font-weight: bold;\n"
	"}\n"
	"\n"
	"div.statcounter h2 {\n"
	" text-align: center;\n"
	" font-size: large;\n"
	" border: 1px solid #000000;\n"
	" background-color: #8080ff;\n"
	" color: #ffffff;\n"
	"}\n"
	"\n"
	"div.statcounter dl {\n"
	" float: left;\n"
	" margin-top: 0;\n"
	" margin-bottom: 0;\n"
	" margin-left: 0;\n"
	" margin-right: 0;\n"
	"}\n"
	"\n"
	"div.statcounter dt {\n"
	" width: 200px;\n"
	" text-align: center;\n"
	" font-weight: bold;\n"
	" border: 0.5px solid #000000;\n"
	" background-color: #8080ff;\n"
	" color: #ffffff;\n"
	"}\n"
	"\n"
	"div.statcounter dd {\n"
	" width: 200px;\n"
	" text-align: right;\n"
	" border: 0.5px solid #000000;\n"
	" background-color: teal;\n"
	" color: #ffffff;\n"
	" margin-left: 0;\n"
	" margin-right: 0;\n"
	"}\n"
	"\n"
	"div.statcounter br {\n"
	" clear: left;\n"
	"}\n"
	" </style>\n"
	" <title>BIND 9 Statistics</title>\n"
	" </head>\n"
	" <body>\n"
	" <div class=\"header\">\n"
	" <h1>Bind 9 Configuration and Statistics</h1>\n"
	" </div>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <table>\n"
	" <tr class=\"rowh\"><th colspan=\"2\">Times</th></tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>boot-time</td>\n"
	" <td><xsl:value-of select=\"server/boot-time\"/></td>\n"
	" </tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>current-time</td>\n"
	" <td><xsl:value-of select=\"server/current-time\"/></td>\n"
	" </tr>\n"
	" </table>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <table>\n"
	" <tr class=\"rowh\"><th colspan=\"2\">Incoming Requests</th></tr>\n"
	" <xsl:for-each select=\"server/requests/opcode\">\n"
	" <tr class=\"lrow\">\n"
	" <td><xsl:value-of select=\"name\"/></td>\n"
	" <td><xsl:value-of select=\"counter\"/></td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <table>\n"
	" <tr class=\"rowh\"><th colspan=\"2\">Incoming Queries</th></tr>\n"
	" <xsl:for-each select=\"server/queries-in/rdtype\">\n"
	" <tr class=\"lrow\">\n"
	" <td><xsl:value-of select=\"name\"/></td>\n"
	" <td><xsl:value-of select=\"counter\"/></td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <xsl:for-each select=\"views/view\">\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"2\">Outgoing Queries from View <xsl:value-of select=\"name\"/></th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"rdtype\">\n"
	" <tr class=\"lrow\">\n"
	" <td><xsl:value-of select=\"name\"/></td>\n"
	" <td><xsl:value-of select=\"counter\"/></td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br/>\n"
	" </xsl:for-each>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <div class=\"statcounter\">\n"
	" <h2>Server Statistics</h2>\n"
	" <xsl:for-each select=\"server/nsstat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br/>\n"
	" </div>\n"
	"\n"
	" <div class=\"statcounter\">\n"
	" <h2>Zone Maintenance Statistics</h2>\n"
	" <xsl:for-each select=\"server/zonestat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br />\n"
	" </div>\n"
	"\n"
	" <div class=\"statcounter\">\n"
	" <h2>Resolver Statistics (Common)</h2>\n"
	" <xsl:for-each select=\"server/resstat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br />\n"
	" </div>\n"
	"\n"
	" <xsl:for-each select=\"views/view\">\n"
	" <div class=\"statcounter\">\n"
	" <h2>Resolver Statistics for View <xsl:value-of select=\"name\"/></h2>\n"
	" <xsl:for-each select=\"resstat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br />\n"
	" </div>\n"
	" </xsl:for-each>\n"
	"\n"
	" <br />\n"
	"\n"
	" <div class=\"statcounter\">\n"
	" <h2>ADB Statistics (Common)</h2>\n"
	" <xsl:for-each select=\"server/adbstat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br />\n"
	" </div>\n"
	"\n"
	" <xsl:for-each select=\"views/view\">\n"
	" <div class=\"statcounter\">\n"
	" <h2>ADB Statistics for View <xsl:value-of select=\"name\"/></h2>\n"
	" <xsl:for-each select=\"adbstat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br />\n"
	" </div>\n"
	" </xsl:for-each>\n"
	"\n"
	" <br />\n"
	"\n"
	" <xsl:for-each select=\"views/view\">\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"2\">Cache Statistics for View <xsl:value-of select=\"name\"/></th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"cachestats/cachestat\">\n"
	" <tr class=\"lrow\">\n"
	" <td><xsl:value-of select=\"name\"/></td>\n"
	" <td><xsl:value-of select=\"value\"/></td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br/>\n"
	" </xsl:for-each>\n"
	"\n"
	" <xsl:for-each select=\"views/view\">\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"2\">Cache DB RRsets for View <xsl:value-of select=\"name\"/></th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"cache/rrset\">\n"
	" <tr class=\"lrow\">\n"
	" <td><xsl:value-of select=\"name\"/></td>\n"
	" <td><xsl:value-of select=\"counter\"/></td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br/>\n"
	" </xsl:for-each>\n"
	"\n"
	" <div class=\"statcounter\">\n"
	" <h2>Socket I/O Statistics</h2>\n"
	" <xsl:for-each select=\"server/sockstat\">\n"
	" <dl>\n"
	" <dt><xsl:value-of select=\"name\"/></dt>\n"
	" <dd><xsl:value-of select=\"counter\"/></dd>\n"
	" </dl>\n"
	" </xsl:for-each>\n"
	" <br/>\n"
	" </div>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <xsl:for-each select=\"views/view\">\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"10\">Zones for View <xsl:value-of select=\"name\"/></th>\n"
	" </tr>\n"
	" <tr class=\"rowh\">\n"
	" <th>Name</th>\n"
	" <th>Class</th>\n"
	" <th>Serial</th>\n"
	" <th>Success</th>\n"
	" <th>Referral</th>\n"
	" <th>NXRRSET</th>\n"
	" <th>NXDOMAIN</th>\n"
	" <th>Failure</th>\n"
	" <th>XfrReqDone</th>\n"
	" <th>XfrRej</th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"zones/zone\">\n"
	" <tr class=\"lrow\">\n"
	" <td>\n"
	" <xsl:value-of select=\"name\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"rdataclass\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"serial\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/QrySuccess\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/QryReferral\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/QryNxrrset\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/QryNXDOMAIN\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/QryFailure\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/XfrReqDone\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"counters/XfrRej\"/>\n"
	" </td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br/>\n"
	" </xsl:for-each>\n"
	"\n"
	" <br/>\n"
	"\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"7\">Network Status</th>\n"
	" </tr>\n"
	" <tr class=\"rowh\">\n"
	" <th>ID</th>\n"
	" <th>Name</th>\n"
	" <th>Type</th>\n"
	" <th>References</th>\n"
	" <th>LocalAddress</th>\n"
	" <th>PeerAddress</th>\n"
	" <th>State</th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"socketmgr/sockets/socket\">\n"
	" <tr class=\"lrow\">\n"
	" <td>\n"
	" <xsl:value-of select=\"id\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"name\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"type\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"references\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"local-address\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"peer-address\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:for-each select=\"states\">\n"
	" <xsl:value-of select=\".\"/>\n"
	" </xsl:for-each>\n"
	" </td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br/>\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"2\">Task Manager Configuration</th>\n"
	" </tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>Thread-Model</td>\n"
	" <td>\n"
	" <xsl:value-of select=\"taskmgr/thread-model/type\"/>\n"
	" </td>\n"
	" </tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>Worker Threads</td>\n"
	" <td>\n"
	" <xsl:value-of select=\"taskmgr/thread-model/worker-threads\"/>\n"
	" </td>\n"
	" </tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>Default Quantum</td>\n"
	" <td>\n"
	" <xsl:value-of select=\"taskmgr/thread-model/default-quantum\"/>\n"
	" </td>\n"
	" </tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>Tasks Running</td>\n"
	" <td>\n"
	" <xsl:value-of select=\"taskmgr/thread-model/tasks-running\"/>\n"
	" </td>\n"
	" </tr>\n"
	" <tr class=\"lrow\">\n"
	" <td>Tasks Ready</td>\n"
	" <td>\n"
	" <xsl:value-of select=\"taskmgr/thread-model/tasks-ready\"/>\n"
	" </td>\n"
	" </tr>\n"
	" </table>\n"
	" <br/>\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"6\">Tasks</th>\n"
	" </tr>\n"
	" <tr class=\"rowh\">\n"
	" <th>ID</th>\n"
	" <th>Name</th>\n"
	" <th>References</th>\n"
	" <th>State</th>\n"
	" <th>Quantum</th>\n"
	" <th>Events</th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"taskmgr/tasks/task\">\n"
	" <tr class=\"lrow\">\n"
	" <td>\n"
	" <xsl:value-of select=\"id\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"name\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"references\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"state\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"quantum\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"events\"/>\n"
	" </td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br />\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"4\">Memory Usage Summary</th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"memory/summary/*\">\n"
	" <tr class=\"lrow\">\n"
	" <td><xsl:value-of select=\"name()\"/></td>\n"
	" <td><xsl:value-of select=\".\"/></td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	" <br />\n"
	" <table>\n"
	" <tr class=\"rowh\">\n"
	" <th colspan=\"10\">Memory Contexts</th>\n"
	" </tr>\n"
	" <tr class=\"rowh\">\n"
	" <th>ID</th>\n"
	" <th>Name</th>\n"
	" <th>References</th>\n"
	" <th>TotalUse</th>\n"
	" <th>InUse</th>\n"
	" <th>MaxUse</th>\n"
	" <th>BlockSize</th>\n"
	" <th>Pools</th>\n"
	" <th>HiWater</th>\n"
	" <th>LoWater</th>\n"
	" </tr>\n"
	" <xsl:for-each select=\"memory/contexts/context\">\n"
	" <tr class=\"lrow\">\n"
	" <td>\n"
	" <xsl:value-of select=\"id\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"name\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"references\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"total\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"inuse\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"maxinuse\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"blocksize\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"pools\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"hiwater\"/>\n"
	" </td>\n"
	" <td>\n"
	" <xsl:value-of select=\"lowater\"/>\n"
	" </td>\n"
	" </tr>\n"
	" </xsl:for-each>\n"
	" </table>\n"
	"\n"
	" </body>\n"
	" </html>\n"
	" </xsl:template>\n"
	"</xsl:stylesheet>\n";
