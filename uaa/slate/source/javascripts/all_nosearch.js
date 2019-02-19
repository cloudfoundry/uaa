//= require ./lib/_energize
//= require ./app/_toc
//= require ./app/_lang
//= require ./app/_version_dropdown
//= require ./lib/_dropdown

$(function() {
  loadToc($('#toc'), '.toc-link', '.toc-list-h2, .toc-list-h3', 10);
  setupLanguages($('body').data('languages'));
  $('.content').imagesLoaded( function() {
    window.recacheHeights();
    window.refreshToc();
  });
});

window.onpopstate = function() {
  activateLanguage(getLanguageFromQueryString());
};
