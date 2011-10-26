/*!
 * jQuery Simple Treeview Plugin
 * Examples and documentation at: http://mkhudon.com/jquery/simpletreeview
 * Copyright (c) 2009 mkhudon
 * Version: 0.1 (20-AUG-2009)
 * Dual licensed under the MIT and GPL licenses:
 * http://www.opensource.org/licenses/mit-license.php
 * http://www.gnu.org/licenses/gpl.html
 * Requires: jQuery v1.2.x or later
 */
(function($){
	
	// Extend jQuery to reverse and shift object arrays
	$.fn.reverse = [].reverse;
	$.fn.shift = [].shift;
	
	// Options:
	//		open - HTML string to display for the opened handle
	//		close - HTML string to display for the closed handle
	//		slide - Boolean flag to indicate if node should slide open/close
	//		speed - Speed of the slide. Can be a string: 'slow', 'fast', or a number of milliseconds: 1000
	//		collapsed - Boolean to indicate if the tree should be collapsed on build
	//		collapse - A node to collapse on build. Can be a string with indexes: '0.1.2' or a jQuery ul: $("#tree ul:eq(1)")
	//		expand - A node to expand on build. Can be a string with indexes: '0.1.2' or a jQuery ul: $("#tree ul:eq(1)")
	$.fn.simpletreeview = function(options) {

		// Override plugin default settings
		var settings = $.extend({}, {
			open:  "&#9660;",
			close: "&#9658;",
			slide: false,
			speed: 'normal',
			collapsed: false,
			collapse: null,
			expand: null }, options);

		var $tree = $(this);

		// Class method to expand the tree's node
		this.expand = function(node) {

			// Find all ul nodes in the object's path to expand...
			var $nodes = this.getNode(node).parents('ul').reverse().andSelf();
			$nodes.shift(); // ... except the root node
	
			expandNode($nodes);
		}

		// Recursive method which expands the specified nodes
		function expandNode($nodes) {

			// Stop recursivity when there are no more nodes to expand
			if($nodes.size() == 0) return;

			// Get the current node
			var $node = $($nodes.get(0));
			$nodes.shift();

			toggle($node, "open", function() {
				expandNode($nodes);
			});
		}

		// Class method to collapse the tree's node
		this.collapse = function(node) {
			collapseNode(this.getNode(node));
		}

		// Recursive method which expands the specified nodes
		function collapseNode($node) {

			// Don't collapse the tree root
			if($node.parent("li").size() == 0) return;

			toggle($node, "close", function() {
				collapseNode($node.parent("li").parent("ul"));
			});
		}

		// Change the state of the specified ul
		// method (optional): should be a string with open or close. toggle by default
		// callback (optional): function to call back after toggle
		function toggle($ul, method, callback) {

			// Set callback to empty function if undefined
			if(callback === undefined) callback = function(){};

			var $handle = $ul.parent("li").children("span.handle");

			if(method == "open") {
				$handle.html(settings.open);

				if(settings.slide) { $ul.slideDown(settings.speed, callback); }
				else { $ul.show(); callback(); }
			}
			else if(method == "close") {

				$handle.html(settings.close);

				if(settings.slide) { $ul.slideUp(settings.speed, callback); }
				else { $ul.hide(); callback(); }
			}
			else {		
					$handle.html($ul.is(':hidden') ? settings.open : settings.close);

					if(settings.slide) { $ul.slideToggle(settings.speed, callback); }
					else { $ul.toggle(); callback(); }
			}
		}

		// Class method that transform the index string (ex: "0.1.2") into a jQuery object
		this.getNode = function(index) {

			if(typeof index != "object") {
				selector = $.map(index.toString().split('.'), function(i) {
					return "li:eq(" + i + ") > ul";
				}).join(" > ");

				index = $tree.find(">" + selector);
			}

			return index;
		}

		function setup($nodes) {

			$nodes.each(function() {
				var $node = $(this); // The current node
				var $ul = $node.children("ul");
				var $childs = $ul.children("li");

				// Check for childs
				if($childs.size() > 0) {

					// Add handle to the node for expanding / collapsing tree
					$node.prepend('<span class="handle">' + (settings.collapsed || $ul.is(":hidden") ? settings.close : settings.open) + '</span>');

					// Hide the childs if tree should be collapsed upon build
					if(settings.collapsed) { $ul.hide(); }

					// Add click function to handle
					$node.children("span.handle").click(function(){
						toggle($ul);
					});

					// Setup the node's childs
					setup($childs);
				}
			});
		}

		// Build tree starting with the root elements
		setup($tree.children("li"));

		// Check to expand after build
		if(settings.expand) {
			this.expand(settings.expand);
		}

		// Check to collapse after build
		if(settings.collapse) {
			this.collapse(settings.collapse);
		}

		// Return the jQuery object to allow for chainability
		return this;
	}
})(jQuery);