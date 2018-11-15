/*
 *
 *  PACrunner - Proxy configuration daemon
 *
 *  Copyright (C) 2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2014  Jolla Ltd. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <tut/tut.hpp>
#include <tut/tut_console_reporter.hpp>
#include <tut/tut_cppunit_reporter.hpp>
#include <tut/tut_main.hpp>
#include <tut/tut_macros.hpp>

#include <string>
#include <sstream>
#include <stdexcept>

extern "C" {
#include "plugin.h"
#include "js.h"
};

#define EXAMPLE_URL	"http://www.example.com/site/test.html"
#define EXAMPLE_HOST	"www.example.com"

#define DIRECT_PAC	"function FindProxyForURL(url, host)\n"		\
			"{\n"						\
			"	return \"DIRECT\";"			\
			"}\n"

#define EXAMPLE_PAC \
	"function FindProxyForURL(url, host)\n"				\
	"{\n"								\
	"  var me = myIpAddress();\n"					\
	"  var resolved_ip = dnsResolve(host);\n"			\
	"  if (me == \"127.0.0.1\") { return \"DIRECT\"; }\n"		\
	"  if (host == \"127.0.0.1\") { return \"DIRECT\"; }\n"		\
	"  if (host == \"localhost\") { return \"DIRECT\"; }\n"		\
	"  if (isPlainHostName(host)) { return \"DIRECT\"; }\n"		\
	"  return \"PROXY proxy.example.com\";\n"			\
	"}\n"

extern "C" const char *pacrunner_proxy_get_script(struct pacrunner_proxy *proxy);
extern "C" const char *pacrunner_proxy_get_interface(struct pacrunner_proxy *proxy);

struct pacrunner_proxy {
    int nr;
    char const *interface;
};

static struct pacrunner_js_driver *driver = nullptr;

static struct pacrunner_proxy proxy_direct = {
    0, "lo"
};
static struct pacrunner_proxy proxy_example = {
    1, "wlan0"
};
static struct pacrunner_proxy proxy_example_direct = {
    1, "lo"
};


extern "C" int pacrunner_js_driver_register(struct pacrunner_js_driver *d)
{
    driver = d;
    return 0;
}

extern "C" void pacrunner_js_driver_unregister(struct pacrunner_js_driver *d)
{
    driver = nullptr;
}

extern "C" const char *pacrunner_proxy_get_script(struct pacrunner_proxy *proxy)
{
    switch(proxy->nr) {
    case 0:
        return DIRECT_PAC;
    case 1:
        return EXAMPLE_PAC;
    default:
        return "";
    }
}

extern "C" const char *pacrunner_proxy_get_interface(struct pacrunner_proxy *proxy)
{
    return proxy->interface;
}

extern struct pacrunner_plugin_desc pacrunner_plugin_desc;

// void *lib_h = nullptr;

// void load()
// {
//     //-Bsymbolic
//     lib_h = dlopen("libpacrunner-cutes.so", RTLD_LAZY);
//     if (!lib_h)
//         std::cerr << dlerror() << std::endl;
// }

namespace tut
{

test_runner_singleton runner;

struct pacrunner_cutes_test
{
    virtual ~pacrunner_cutes_test()
    {
    }
};

typedef test_group<pacrunner_cutes_test> tf;
typedef tf::object object;
tf cor_pacrunner_cutes_test("pacrunner_cutes");

enum test_ids {
    tid_register = 1
    , tid_direct
    , tid_other
};

template<> template<>
void object::test<tid_register>()
{
    std::string expected("cutes");
    std::string real(pacrunner_plugin_desc.name);
    ensure_eq("Plugin name", real, expected);
    pacrunner_plugin_desc.init();
    ensure("Initialized", driver);
    pacrunner_plugin_desc.exit();
    ensure("Freed", !driver);
}

template<> template<>
void object::test<tid_direct>()
{
    pacrunner_plugin_desc.init();
    ensure("Initialized", driver);

    driver->set_proxy(&proxy_direct);
    std::string res(driver->execute(EXAMPLE_URL, EXAMPLE_HOST));
    ensure_eq("Proxy", res, std::string("DIRECT"));
    pacrunner_plugin_desc.exit();
    ensure("Freed", !driver);
}

template<> template<>
void object::test<tid_other>()
{
    pacrunner_plugin_desc.init();
    ensure("Initialized", driver);
    driver->set_proxy(&proxy_example);
    std::string res(driver->execute(EXAMPLE_URL, EXAMPLE_HOST));
    ensure_eq("Proxy", res, std::string("PROXY proxy.example.com"));

    res = driver->execute("http://127.0.0.1", "127.0.0.1");
    ensure_eq("Proxy", res, std::string("DIRECT"));

    driver->set_proxy(&proxy_example_direct);
    res = driver->execute(EXAMPLE_URL, EXAMPLE_HOST);
    ensure_eq("Proxy", res, std::string("DIRECT"));
    pacrunner_plugin_desc.exit();
    ensure("Freed", !driver);
}

}

int main(int argc, const char *argv[])
{
    tut::console_reporter reporter;
    tut::runner.get().set_callback(&reporter);
    try
    {
        if(tut::tut_main(argc, argv))
        {
            if(reporter.all_ok()) {
                return 0;
            } else {
                std::cerr << std::endl;
                std::cerr << "tests are failed" << std::endl;
            }
        }
    }
    catch(const tut::no_such_group &ex) {
        std::cerr << "No such group: " << ex.what() << std::endl;
    }
    catch(const tut::no_such_test &ex) {
        std::cerr << "No such test: " << ex.what() << std::endl;
    }
    catch(const tut::tut_error &ex) {
        std::cout << "General error: " << ex.what() << std::endl;
    }

    return -1;
}
