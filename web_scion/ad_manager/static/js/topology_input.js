
function sanitize(loadenString) {
    loadenString = loadenString.replace(/&#39;/g, '"');
    loadenString = loadenString.replace(/True/g, '"True"');
    loadenString = loadenString.replace(/False/g, '"False"');
    return loadenString;
}

function parseTopology(reloadedTopology) {
    reloadedTopology = sanitize(reloadedTopology);
    reloadedTopology = JSON.parse(reloadedTopology);
    return reloadedTopology;
}

function setLoadedTopology(reloadedTopology) {
    var isCore = reloadedTopology['Core'];
    $('#inputIsCore.shownCheckbox').prop('checked', isCore);
    delete reloadedTopology['Core'];
    var dnsDomain = reloadedTopology['DnsDomain'];
    $('#inputDnsDomain').attr('value', dnsDomain);
    delete reloadedTopology['DnsDomain'];
    var mtu = reloadedTopology['MTU'];
    $('#inputMTU').attr('value', mtu);
    delete reloadedTopology['MTU'];
    var isd_as = reloadedTopology['ISD_AS'];
    delete reloadedTopology['ISD_AS'];

    for (var entryKey in reloadedTopology) {
        if (entryKey.endsWith("Servers")) {
            var entry = reloadedTopology[entryKey];
            var type = entryKey.slice(0,-7); // remove the 'Server' part
            if (type == 'DNS') {
                type = 'Domain';
            }
            //var typeValue = type.toLowerCase() + '_server';
            //$('#input'+type+'ServerType').attr('value', typeValue); // already set
            var name = Object.keys(entry)[0];
            $('#input'+type+'ServerName').attr('value', name);
            var server = entry[name];
            var address = server['Addr'];
            $('#input'+type+'ServerAddress').attr('value', address);

            // remove entry
            delete reloadedTopology[entryKey]
        }
    }

    for (var edgeRouterKey in reloadedTopology['EdgeRouters']) {
        var edgeRouter = reloadedTopology['EdgeRouters'][edgeRouterKey];
        var name = edgeRouterKey;
        $('#inputEdgeRouterName').attr('value', name);
        var address = edgeRouter['Addr'];
        $('#inputEdgeRouterAddress').attr('value', address);

        var interface = edgeRouter['Interface'];
        for (var interfaceKey in interface) {
            var value = interface[interfaceKey];
            switch(interfaceKey) {
                case 'ISD_AS':
                    $('#inputInterfaceRemoteName').attr('value', value);
                    break;
                case 'LinkType':
                    $('#inputInterfaceType').attr('value', value);
                    break;
                case 'ToAddr':
                    $('#inputInterfaceRemoteAddress').attr('value', value);
                    break;
                case 'ToUdpPort':
                    $('#inputInterfaceRemotePort').attr('value', value);
                    break;
                case 'UdpPort':
                    $('#inputInterfaceOwnPort').attr('value', value);
                    break;
                default: // Addr, Bandwidth, IFID
                    $('#inputInterface'+interfaceKey).attr('value', value);
            }
        }
    }

    delete reloadedTopology['EdgeRouters'];

    var zookeepers = reloadedTopology['Zookeepers'];

    for (var zkKey in zookeepers) {
        var server = zookeepers[zkKey]; //inputZookeeperServerType
        //$('#inputZookeeperServerType').attr('value', 'zookeeper_server'); // already set
        var address = server['Addr'];
        $('#inputZookeeperServerAddress').attr('value', address);
        var port = server['Port'];
        $('#inputZookeeperServerPort').attr('value', port);
    }
}

