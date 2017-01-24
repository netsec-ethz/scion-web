function checkFreshness(isd_id, as_id) {
    var csrftoken = $("input[name='csrfmiddlewaretoken']").attr('value');
    var xmlhttp = new XMLHttpRequest();
    var url = "../../api/v1/internal/isd/" + isd_id + "/as/" + as_id + "/topo_hash";
    var submit = false;
    xmlhttp.onreadystatechange = function () {
        // check if XMLHttpRequest is ready and HTTP status code is 200
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            var response = xmlhttp.responseText;
            if (response != "") { // don't try to parse empty answer
                var res = JSON.parse(response);
                // check if data has changed since page loading
                var changes = res['topo_hash'] != reloadedTopologyHash;
                // check if force submitting is enabled
                var forceSubmit = $('#forceSubmit:checked').length > 0;
                
                if (changes && !forceSubmit) {
                    overlayAlert("The data has changed, please reload the page or force submit.", 3000);
                    $('#forceSubmitDiv').removeClass('hidden');
                    $('#submitButton')[0].innerHTML = "Save to topology file";
                    // abort POST
                    submit = false;
                } else if (!ifidUnique()) {
                    overlayAlert("Your IFIDs are not unique within this AS. Please have a different IFID for each border router.", 3000);
                    $('#submitButton')[0].innerHTML = "Save to topology file";
                } else {
                    overlayAlert("Data submitted", 1000);
                    submit = true;
                    document.getElementById("topologyForm").submit();
                }
            }
        }
        return submit;
    };
    $('#submitButton')[0].innerHTML = "Submitting...";
    xmlhttp.open("POST", url, true);
    xmlhttp.setRequestHeader("X-CSRFToken", csrftoken);
    xmlhttp.send();
    return submit;
}

function overlayAlert(message, duration) {
    var pageOverlay = document.createElement("div");
    var bodyHeight = document.body.scrollHeight;
    pageOverlay.setAttribute("class", "page-overlay");
    pageOverlay.setAttribute("style", "height: " + bodyHeight + "px;");
    var messageBox = document.createElement("div");
    messageBox.innerHTML = message;
    messageBox.setAttribute("class", "page-overlay-message-box");
    pageOverlay.appendChild(messageBox);
    setTimeout(function () {
        pageOverlay.parentNode.removeChild(pageOverlay);
    }, duration);
    document.body.appendChild(pageOverlay);
}

function ifidUnique() {
    // checks that IFIDs are unique within AS
    var ifidUnique = true;
    var ifidList = [];
    $(".ifid-input").each(function () {
        var ifid = $(this).val();
        var unique = $.inArray(ifid, ifidList) == -1;
        ifidList.push(ifid);
        if (!unique) {
            ifidUnique = false;
            return false; // break the for each loop
        }
    });
    return ifidUnique;
}

function sanitize(loadenString) {
    loadenString = loadenString.replace(/&#39;/g, '"');
    loadenString = loadenString.replace(/True/g, '"True"');
    loadenString = loadenString.replace(/False/g, '"False"');
    loadenString = loadenString.replace(/None/g, '""');
    return loadenString;
}

function parseTopology(reloadedTopology) {
    reloadedTopology = sanitize(reloadedTopology);
    reloadedTopology = JSON.parse(reloadedTopology);
    return reloadedTopology;
}

function toggleInput(elem) {
    // Add or removes a section from the input form when corresponding icon is clicked

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
        var currentName = $(clone).find('.server-name-input').attr('value');
        var nameParts = currentName.split('-');
        nameParts[nameParts.length - 1]++;
        var newName = nameParts.join('-');
        $(clone).find('.server-name-input').attr('value', newName);
        // reset IP
        $(clone).find('.server-address-input').val('');
        
        // Auto-increment IFID if it is router element
        if (clone.attr('class').indexOf('routerItem') > -1) {
            var currentIFID = $(clone).find('.ifid-input').attr('value');
            var newIFID = parseInt(currentIFID) + 1;
            $(clone).find('.ifid-input').attr('value', newIFID);
        }
        
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
    var isCore = reloadedTopology['Core'] == 'True';
    $('#inputIsCore.shownCheckbox').prop('checked', isCore);
    delete reloadedTopology['Core'];

    var mtu = reloadedTopology['MTU'];
    $('#inputMTU').attr('value', mtu);
    delete reloadedTopology['MTU'];

    delete reloadedTopology['ISD_AS']; // set by template

    for (var entryKey in reloadedTopology) {
        if (entryKey.endsWith("Servers")) {
            reloadServerSection(reloadedTopology, entryKey);
            delete reloadedTopology[entryKey]; // remove entry
        }
    }

    reloadRouterSection(reloadedTopology);
    delete reloadedTopology['BorderRouters'];

    var zookeepers = reloadedTopology['Zookeepers'];
    reloadZookeeperSection(zookeepers);
}

function reloadServerSection(reloadedTopology, entryKey) {
    var names;
    var name;

    var server;
    var address;
    var port;
    var addressInternal;
    var portInternal;

    var entry = reloadedTopology[entryKey];
    var type = entryKey.slice(0, -7); // remove the 'Server' part
    //var typeValue = type.toLowerCase() + '_server';
    //$('#input'+type+'ServerType').attr('value', typeValue); // typeValue already set in template
    names = Object.keys(entry); // get a list of keys

    for (var i in names) {
        name = names[i];
        if (i > 0) {
            // if more than one entry, create additional form input
            $('.' + type + 'Item' + ':last').find('.btn-success').click()
        }
        // fill form values
        var itemSelector = '#' + type + 'Item-' + (parseInt(i) + 1).toString(); // get a 1 based selector
        $(itemSelector + ' #input' + type + 'ServerName').val(name);
        server = entry[name];
        address = server['Addr'];
        $(itemSelector + ' #input' + type + 'ServerAddress').val(address);
        port = server['Port'];
        $(itemSelector + ' #input' + type + 'ServerPort').val(port);
        addressInternal = server['AddrInternal'];
        $(itemSelector + ' #input' + type + 'ServerInternalAddress').val(addressInternal);
        portInternal = server['PortInternal'];
        $(itemSelector + ' #input' + type + 'ServerInternalPort').val(portInternal);
    }
}

function reloadZookeeperSection(zookeepers) {
    var server;
    var address;
    var port;

    for (var zkKey in zookeepers) {
        server = zookeepers[zkKey]; //inputZookeeperServerType
        //$('#inputZookeeperServerType').attr('value', 'zookeeper_server'); // already set
        address = server['Addr'];
        $('#inputZookeeperServerAddress').attr('value', address);
        port = server['Port'];
        $('#inputZookeeperServerPort').attr('value', port);
    }
}

function reloadRouterSection(reloadedTopology) {
    var borderRouterIndex = 0;
    var type = 'router';

    var itemSelector;
    var address;
    var port;

    for (var borderRouterKey in reloadedTopology['BorderRouters']) {
        var borderRouter = reloadedTopology['BorderRouters'][borderRouterKey];
        var name = borderRouterKey;
        if (borderRouterIndex > 0) {
            // if more than one entry, create additional form input
            $('.' + type + 'Item' + ':last').find('.btn-success').click()
        }
        itemSelector = '#' + type + 'Item-' + (parseInt(borderRouterIndex) + 1).toString() + ' ';
        $(itemSelector + '#inputBorderRouterName').attr('value', name);
        address = borderRouter['Addr'];
        $(itemSelector + '#inputBorderRouterAddress').attr('value', address);
        $(itemSelector + '#inputBorderRouterAddress').val(address);
        port = borderRouter['Port'];
        $(itemSelector + '#inputBorderRouterPort').attr('value', port);

        var interface_obj = borderRouter['Interface'];
        reloadRouterInterfaceSection(interface_obj, itemSelector);

        borderRouterIndex++;
    }
}

function reloadRouterInterfaceSection(interface_obj, itemSelector) {
    for (var interfaceKey in interface_obj) {
        var value = interface_obj[interfaceKey];
        switch (interfaceKey) {
            case 'ISD_AS':
                $(itemSelector + '#inputInterfaceRemoteName').attr('value', value);
                break;
            case 'LinkType':
                var linkType = $(itemSelector + '#inputInterfaceType');
                $(linkType).attr('value', value);
                // we need to test if the AS is core, so that in case the link type is routing, the option gets added
                checkShowCoreOption();
                // remove all previous selected options for this select
                $(linkType).find("option").removeProp("selected");
                // set selected option
                $(linkType).find('option[value="' + value + '"]').attr('selected', 'selected');
                break;
            case 'MTU':
                $(itemSelector + '#inputLinkMTU').attr('value', value);
                break;
            case 'ToAddr':
                $(itemSelector + '#inputInterfaceRemoteAddress').attr('value', value);
                break;
            case 'ToUdpPort':
                $(itemSelector + '#inputInterfaceRemotePort').attr('value', value);
                break;
            case 'UdpPort':
                $(itemSelector + '#inputInterfaceOwnPort').attr('value', value);
                break;
            default: // Addr, Bandwidth, IFID
                $(itemSelector + '#inputInterface' + interfaceKey).attr('value', value);
        }
    }
}


function gatherIPsforCloudEngines() {
    var ipList = [];
    var parent = $('.cloudEngineItemList');

    $(".server-address-input").each(function() {
        var ipAddress = $(this).val();
        ipAddress = ipAddress.split('/')[0];
        if (ipAddress.length > 0) {
            var unique = $.inArray(ipAddress, ipList) == -1;
            if (unique) {
                ipList.push(ipAddress);
            }
        }
    });

    //clear previous list
    $(parent).empty();

    //fill new list
    for (var i = 0; i < ipList.length; i++) {
        var clone = $('.cloudEngineItemModel').clone();
        $(clone).children('.server-cloud-address-input').val(ipList[i]);
        $(clone).removeClass('hidden');
        $(clone).removeClass('cloudEngineItemModel');
        parent.append($(clone));
    }
}
