using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reecon
{
    class GraphQL
    {
        // Just info here

        /*
        
        // Mass Dump: {__schema{types{name,fields{name description}}}}

         Query Entire Schema: {__schema{types{name description}}}
        --> Shows name + description - Eg: "Ping"

        Query fields of specific Type: { __type(name: "Ping"){fields{name}}}
        --> Shows fields in "Ping" - Eg: ip, output

        Query Specific Value: {Ping(ip:"127.0.0.1") { output }}

        Run a Mutation: {"query":"mutation{ UpdatePassword(email: \"reelix2@gmail.com\", username: \"reelix2\", password: \"reelix2\") { message } }"}


        */
    }
}
