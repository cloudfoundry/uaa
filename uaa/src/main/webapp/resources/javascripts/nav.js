$(document).ready(function() {
  $(".dropdown-trigger").click(function() {
    var $el = $(this);
    $el.toggleClass("open");
    $el.next(".dropdown-content").toggleClass("open");
  });
});