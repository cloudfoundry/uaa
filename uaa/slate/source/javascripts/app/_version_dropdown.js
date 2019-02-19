//= require ../lib/_lunr


(function() {
    'use strict';

    var originalSearchResults, originalDropdownLinks;
    var searchResults, dropdownLinks;

    var index = new lunr.Index();

    index.ref('id');
    index.field('title', {boost: 10});
    index.field('body');
    index.pipeline.add(lunr.trimmer, lunr.stopWordFilter);

    $(setupVersionsDropdown);

    function captureOriginal() {
        originalSearchResults = $('#version-list').clone();
        originalDropdownLinks = originalSearchResults.find('.version-link').clone();
    }

    function bindDropdownPointers() {
        dropdownLinks = $('.dropdown-content .version-link');
    }

    function restoreOriginalContent() {
        searchResults.html(originalSearchResults.html());
    }

    function bindFilter() {
        searchResults = $('#version-list');
    }

    function findMatchingLinkFromOriginal(id) {
        var match = originalDropdownLinks.filter("#" + id)[0];
        return match;
    }

    function displaySearchResults(results) {
        $.each(results, function (index, result) {
            var matchingLink = findMatchingLinkFromOriginal(result.ref);
            searchResults.append(matchingLink);
        });
    }

    function populateFilter() {
        dropdownLinks.each(function() {
            var link = $(this);

            index.add({
                id: link.prop('id'),
                title: link.text(),
                href: link.href
            });
        });
    }

    function setupVersionsDropdown() {
        $.get(
            "../../versions.json",
            function(data) {
                var versions = data.versions 
                // var versions =
                //   [
                //     "4.6.0-SNAPSHOT",
                //     "release-candidate"
                //   ];
                for(var i = 0; i < versions.length; i++) {
                    var version = versions[i];
                    if(version == "release-candidate") { continue; }
                    var li = '<li><a id="version-link-' + version + '"' + ' class="version-link" href="../../version/' + version + '">' + version + '</a></li>';
                    $('#version-list').append(li);
                }

                captureOriginal();
                bindDropdownPointers();
                populateFilter();
                bindFilter();
            }
        );
    }
})();
