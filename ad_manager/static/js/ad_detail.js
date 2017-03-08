/*
 * Copyright 2017 ETH Zurich
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function appendLoadingIndicator(element) {
    var imgPath = '/static/img/ajax-loader.gif';
    var status = element.first();
    if (!status.html().contains(imgPath)) {
        status.append('&nbsp;&nbsp;<img src="' + imgPath + '" />');
    }
}

function showLoadingIndicator(element) {
    element.first().html('');
    appendLoadingIndicator(element);
}

function initServerStatus() {
    $('td div.status-text').html('<b>...</b>');
}

function updateServerStatus() {
    //adDetailUrl // placeholder until decided on Ansible / prometheus.io library
}

function initTopologyCheck() {
    $('#topology-info').hide();
    $('#update-topology-btn').hide();
    $('#push-update-topology-btn').hide();
}

function makeTabsPersistent() {
    // Make tabs persistent. Check https://gist.github.com/josheinstein/5586469
    if (location.hash.substr(0, 2) == "#!") {
        $("a[href='#" + location.hash.substr(2) + "']").tab("show");
    }
    var $tabLink = $("a[data-toggle='tab']");
    $tabLink.on("shown.bs.tab", function (e) {
        var hash = $(e.target).attr("href");
        if (hash.substr(0, 1) == "#") {
            location.replace("#!" + hash.substr(1));
        }
    });
}

function setAccordionExpansion() {
    var expansionSetting = location.hash.indexOf('&expanded_routers');
    if (expansionSetting > -1) {
        var accordionElements = $('.accordion.collapse');
        for (var i=0; i< accordionElements.length; i++) {
            var elem = accordionElements[i];
            if ($(elem)[0].id != "routerAccordion") {
                $(elem).removeClass('in');
            } else {
                $(elem).addClass('in');
            }
        }
    }
    location.hash = location.hash.substr(0, expansionSetting)
}

function statusControl() {
    // Process START/STOP button clicks
    $('.process-control-form > button').click(function (e) {
        var $form = $(this).parent();
        var btnName = $(this).attr('name');
        $.ajax({
            data: $form.serialize() + "&" + btnName, // form data + button
            type: $form.attr('method'),
            url: $form.attr('action'),
            dataType: 'json'
        }).always(function (response) {
            updateServerStatus();
        });
        var $statusCell = $form.parent().siblings('.status-text');
        appendLoadingIndicator($statusCell);
        return false;
    });
}

function displayLogs() {
    // Callbacks for showing log dialogs

    function refreshLog(logUrl) {
        var $logOutput = $('#log-output');
        showLoadingIndicator($logOutput);
        $.ajax({
            url: logUrl,
            dataType: "json"
        }).done(function (result) {
            $logOutput.text(result['data']);
        }).fail(function (a1, a2, a3) {
            $logOutput.text('Something went wrong.')
        });
    }

    var $logWindow = $('#logModal');

    // Open log modal window
    $('.status-text').click(function () {
        var logUrl = $(this).data('log-url');
        refreshLog(logUrl);
        $logWindow.modal();
        $logWindow.data('url', logUrl);
    });

    // Refresh log button
    $('#refresh-log').click(function () {
        var logUrl = $logWindow.data('url');
        refreshLog(logUrl);
    });
}

$(document).ready(function () {
    // "Are you sure?" confirmation boxes
    $('.click-confirm').click(function (e) {
        var confirmation = $(this).data('confirmation') || 'Are you sure?';
        var res = confirm(confirmation);
        if (!res) {
            e.stopImmediatePropagation();
        }
        return res;
    });

    // Status tab callbacks
    initServerStatus();
    updateServerStatus();
    $("#update-ad-btn").click(function () {
        updateServerStatus();
    });

    // Topology tab callbacks
    initTopologyCheck();

    setAccordionExpansion();

    makeTabsPersistent();

    // Update server status when the first tab is opened
    var $tabLink = $("a[data-toggle='tab']");
    $tabLink.on("shown.bs.tab", function (e) {
        if ($(e.target).attr('href') == '#servers') {
            updateServerStatus();
        }
    });

    // Status control forms
    statusControl();

    // Display log files
    displayLogs();
});


// Query github for the last Hashes
function queryForHashes(datalistId) {
    var gitBaseUrl = "https://api.github.com/repos";
    var organisation = "/netsec-ethz";
    var repo = "/scion/";

    $(datalistId).children().slice(1).remove(); // remove previous entries

    var lastWeek = new Date();
    var weekLength = 7; // 7 days per week
    var weekCount = 2; // by default, if no userSetWeekCount set or invalid
    var userSetWeekCount = $('#backLog').val();
    if (userSetWeekCount != '' && !isNaN(userSetWeekCount)) { // failsafe invalid values
        weekCount = Number(userSetWeekCount);
    }

    lastWeek.setDate(new Date().getDate() - (weekCount*weekLength));  //  set date for x weeks ago
    var sinceDate = lastWeek.toISOString();  // get ISO 8601 representation
    var query = "commits?page=1&since=" + sinceDate;  // get all commits since x weeks ago

    var url = gitBaseUrl + organisation + repo + query;

    $.getJSON(url, function (data) {
        $.each(data, function (key, val) {
            var sha = val['sha'];
            var comment = val['commit']['message'].substr(0, 25);
            $(datalistId).append('<option value="' + sha + ' |      ' + comment + '..."></option>');
        });
    });
}
