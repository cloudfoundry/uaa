function CopyToClipboard() {
    var r = document.createRange();
    r.selectNode(document.getElementById('passcode'));
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
}
document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('copybutton').addEventListener('click', CopyToClipboard);
});
