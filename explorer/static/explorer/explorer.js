var csrf_token = $.cookie("csrftoken");
$.ajaxSetup({
	beforeSend: function (xhr) {
		xhr.setRequestHeader("X-CSRFToken", csrf_token);
	},
});

function ExplorerEditor(queryId, dataUrl) {
	this.queryId = queryId;
	this.dataUrl = dataUrl;
	this.$table = $("#preview");
	this.$rows = $("#rows");
	this.$form = $("form");
	this.$snapshotField = $("#id_snapshot");
	this.$paramFields = this.$form.find(".param");

	this.$submit = $("#refresh_play_button, #save_button");

	if (!this.$submit.length) {
		this.$submit = $("#refresh_button");
	}

	this.editor = CodeMirror.fromTextArea(document.getElementById("id_sql"), {
		mode: "text/x-sql",
		lineNumbers: "t",
		autofocus: true,
		height: 500,
		extraKeys: {
			"Ctrl-Enter": function () {
				this.doCodeMirrorSubmit();
			}.bind(this),
			"Cmd-Enter": function () {
				this.doCodeMirrorSubmit();
			}.bind(this),
			"Cmd-/": function () {
				this.editor.toggleComment();
			}.bind(this),
		},
	});
	this.editor.on("change", function (cm, change) {
		document.getElementById("id_sql").classList.add("changed-input");
	});
	this.bind();
}

ExplorerEditor.prototype.getParams = function () {
	var o = false;
	if (this.$paramFields.length) {
		o = {};
		this.$paramFields.each(function () {
			o[$(this).data("param")] = $(this).val();
		});
	}
	return o;
};

ExplorerEditor.prototype.serializeParams = function (params) {
	var args = [];
	for (var key in params) {
		args.push(key + "%3A" + params[key]);
	}
	return args.join("%7C");
};

ExplorerEditor.prototype.doCodeMirrorSubmit = function () {
	// Captures the cmd+enter keystroke and figures out which button to trigger.
	this.$submit.click();
};

ExplorerEditor.prototype.savePivotState = function (state) {
	bmark = btoa(
		JSON.stringify(
			_(state).pick("aggregatorName", "rows", "cols", "rendererName", "vals")
		)
	);
	$el = $("#pivot-bookmark");
	$el.attr("href", $el.data("baseurl") + "#" + bmark);
};

ExplorerEditor.prototype.updateQueryString = function (key, value, url) {
	// http://stackoverflow.com/a/11654596/221390
	if (!url) url = window.location.href;
	var re = new RegExp("([?&])" + key + "=.*?(&|#|$)(.*)", "gi");

	if (re.test(url)) {
		if (typeof value !== "undefined" && value !== null)
			return url.replace(re, "$1" + key + "=" + value + "$2$3");
		else {
			var hash = url.split("#");
			url = hash[0].replace(re, "$1$3").replace(/(&|\?)$/, "");
			if (typeof hash[1] !== "undefined" && hash[1] !== null)
				url += "#" + hash[1];
			return url;
		}
	} else {
		if (typeof value !== "undefined" && value !== null) {
			var separator = url.indexOf("?") !== -1 ? "&" : "?",
				hash = url.split("#");
			url = hash[0] + separator + key + "=" + value;
			if (typeof hash[1] !== "undefined" && hash[1] !== null)
				url += "#" + hash[1];
			return url;
		} else return url;
	}
};

ExplorerEditor.prototype.formatSql = function () {
	$.post(
		"../format/",
		{ sql: this.editor.getValue() },
		function (data) {
			this.editor.setValue(data.formatted);
		}.bind(this)
	);
};

ExplorerEditor.prototype.showRows = function () {
	var rows = this.$rows.val(),
		$form = $("#editor");
	$form.attr(
		"action",
		this.updateQueryString("rows", rows, window.location.href)
	);
	$form.submit();
};

ExplorerEditor.prototype.bind = function () {
	$("#show_schema_button").click(function () {
		$("#schema_frame").attr("src", "../schema/");
		$("#query_area").addClass("col-md-9");
		var schema$ = $("#schema");
		schema$.addClass("col-md-3");
		schema$.show();
		$(this).hide();
		$("#hide_schema_button").show();
		return false;
	});

	$("#hide_schema_button").click(function () {
		$("#query_area").removeClass("col-md-9");
		var schema$ = $("#schema");
		schema$.removeClass("col-md-3");
		schema$.hide();
		$(this).hide();
		$("#show_schema_button").show();
		return false;
	});

	$("#format_button").click(
		function (e) {
			e.preventDefault();
			this.formatSql();
		}.bind(this)
	);

	$("#save_button").click(
		function () {
			var params = this.getParams(this);
			if (params) {
				this.$form.attr(
					"action",
					"../" + this.queryId + "/?params=" + this.serializeParams(params)
				);
			}
			this.$snapshotField.hide();
			this.$form.append(this.$snapshotField);
		}.bind(this)
	);

	$("#refresh_button").click(
		function (e) {
			e.preventDefault();
			var params = this.getParams();
			if (params) {
				window.location.href =
					"../" + this.queryId + "/?params=" + this.serializeParams(params);
			} else {
				window.location.href = "../" + this.queryId + "/";
			}
		}.bind(this)
	);

	$("#refresh_play_button").click(
		function () {
			this.$form.attr("action", "../play/");
		}.bind(this)
	);

	$("#playground_button").click(
		function () {
			this.$form.prepend("<input type=hidden name=show value='' />");
			this.$form.attr("action", "../play/");
		}.bind(this)
	);

	$("#download_play_button").click(
		function () {
			this.$form.attr("action", "../csv");
		}.bind(this)
	);

	$(".download_button").click(
		function (e) {
			e.preventDefault();
			var dl_link = "download";
			var params = this.getParams(this);
			if (params) {
				dl_link = dl_link + "?params=" + this.serializeParams(params);
			}
			window.open(dl_link, "_blank");
		}.bind(this)
	);

	$("#create_button").click(
		function () {
			this.$form.attr("action", "../new/");
		}.bind(this)
	);

	$(".stats-expand").click(
		function (e) {
			e.preventDefault();
			$(".stats-expand").hide();
			$(".stats-wrapper").show();
			this.$table.floatThead("reflow");
		}.bind(this)
	);

	$(".sort").click(
		function (e) {
			var t = $(e.target).data("sort");
			var dir = $(e.target).data("dir");
			$(".sort").css(
				"background-image",
				"url(http://cdn.datatables.net/1.10.0/images/sort_both.png)"
			);
			if (dir == "asc") {
				$(e.target).data("dir", "desc");
				$(e.target).css(
					"background-image",
					"url(http://cdn.datatables.net/1.10.0/images/sort_asc.png)"
				);
			} else {
				$(e.target).data("dir", "asc");
				$(e.target).css(
					"background-image",
					"url(http://cdn.datatables.net/1.10.0/images/sort_desc.png)"
				);
			}
			var vals = [];
			var ct = 0;
			while (ct < this.$table.find("th").length) {
				vals.push(ct++);
			}
			var options = {
				valueNames: vals,
			};
			var tableList = new List("preview", options);
			tableList.sort(t, { order: dir });
		}.bind(this)
	);

	$("#preview-tab-label").click(
		function () {
			this.$table.floatThead("reflow");
		}.bind(this)
	);

	var pivotState = window.location.hash;
	var navToPivot = false;
	if (!pivotState) {
		pivotState = { onRefresh: this.savePivotState };
	} else {
		pivotState = JSON.parse(atob(pivotState.substr(1)));
		pivotState["onRefresh"] = this.savePivotState;
		navToPivot = true;
	}

	$(".pivot-table").pivotUI(this.$table, pivotState);
	if (navToPivot) {
		$("#pivot-tab-label").tab("show");
	}

	this.$table.floatThead({
		scrollContainer: function () {
			return this.$table.closest(".overflow-wrapper");
		}.bind(this),
	});

	this.$rows.change(
		function () {
			this.showRows();
		}.bind(this)
	);
	this.$rows.keyup(
		function (event) {
			if (event.keyCode == 13) {
				this.showRows();
			}
		}.bind(this)
	);
};

$(window).on("beforeunload", function () {
	// Only do this if changed-input is on the page and we're not on the playground page.
	if ($(".changed-input").length && !$(".playground-form").length) {
		return "You have unsaved changes to your query.";
	}
});

// Disable unsaved changes warning when submitting the editor form
$(document).on("submit", "#editor", function (event) {
	// disable warning
	$(window).off("beforeunload");
});
