
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

function toggleInput(elem) {
        var accordion = $(elem).parents('.accordion');
        var currentClass = $(elem).children(':first').attr('class'); // either glyphicon glyphicon-{plus|minus}
        if (currentClass === 'glyphicon glyphicon-plus') {
            var clone = $(elem).parents('.item').clone();
            // update clone id
            var oldId = clone.attr('id').split('-');
            var idName = oldId[0];
            var newIdNo = parseInt(oldId[1]) + 1;
            $(clone).attr('id', idName + '-' + newIdNo.toString());
            // increment current name for next field
            var currentName = $(clone).find( '.server-name-input' ).attr('value');
            var nameParts = currentName.split('-');
            nameParts[nameParts.length-1]++;
            var newName = nameParts.join('-');
            $(clone).find('.server-name-input').attr('value', newName);
            // reset IP
            $(clone).find( '.server-address-input' ).val('');
            // append the cloned and cleaned item
            accordion.append(clone);
            //var test = $(clone).children(':first').prop('tagName');
            if ($(clone).children(':first').attr('class') !== 'doc-hr') {
                // add separator
                $(clone).prepend('<div class="doc-hr"></div>');
            }
            $(elem).removeClass('btn-success').addClass('btn-danger');
            $(elem).children(':first').removeClass('glyphicon glyphicon-plus').addClass('glyphicon glyphicon-minus');
        } else {
            var sibling = $(elem).parents('.item').next();
            var firstItem = accordion.children(':nth-child(2)');
            var selfItem = $(elem).parents('.item');
            if (firstItem.is(selfItem)) {
                $(sibling).children(':first').remove();
            }
            selfItem.remove();
        }
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
            //$('#input'+type+'ServerType').attr('value', typeValue); // typeValue already set in template
            var names = Object.keys(entry); // get a list of keys

            for (var i in names) {
                var name = names[i];
                if (i > 0) {
                    // if more than one entry, create additional form input
                    $('.' + type + 'Item'+':last').find('.btn-success').click()
                }
                // fill form values
                var itemSelector = '#' + type + 'Item-' + (parseInt(i) + 1).toString();
                $(itemSelector + ' #input'+type+'ServerName').val(name);
                var server = entry[name];
                var address = server['Addr'];
                $(itemSelector + ' #input'+type+'ServerAddress').val(address);
                var port = server['Port'];
                $(itemSelector + ' #input'+type+'ServerPort').val(port);
            }

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

