function macfilter_change($e) {
    var v = $e.val();
    var $mldiv = $e.parents('div.form-group:first').next();
    if (v == 'disable') {
	$mldiv.slideUp();
    }
    else {
	if (v == 'allow') {
	    $('.allow-macaddr', $mldiv).removeClass('hidden');
	    $('.deny-macaddr', $mldiv).addClass('hidden');
	}
	else {
	    $('.allow-macaddr', $mldiv).addClass('hidden');
	    $('.deny-macaddr', $mldiv).removeClass('hidden');
	}
	$mldiv.slideDown();
    }
}

function encryption_change($e) {
    var v = $e.val();
    if (v == null || v == 'none') {
	$e.parents('div.form-group:first').next().slideUp().next().slideUp();
    }
    else {
	$e.parents('div.form-group:first').next().slideDown().next().slideDown();
    }
}

function adjustModalBackDrop() {
    var h1 = $('#calendar-dialog .modal-backdrop').height();
    var h2 = $('#calendar-dialog .modal-dialog').height() + 150;
    $('#calendar-dialog .modal-backdrop').height(h1 > h2 ? h1 : h2);
}

function wifi_schedule_change() {
    var v = $('input[name=alwayson-chk]:checked').val();
    if (v == '1') {
	$('#calendar-container').slideUp();
	$('#extend-time').slideUp();
	$('#extend-time-alert').slideUp();
    }
    else {
	$('#extend-time').slideDown();
	if ($('#extend-time-alert').data('extended')) {
	    $('#extend-time-alert').slideDown();
	}
	$('#calendar-container').slideDown(400, function() {
	    $('#calendar-tabs a:first').trigger('shown.bs.tab');
	    adjustModalBackDrop();
	});
    }
}

$('input[name=alwayson-chk]').on('click', function() {
    wifi_schedule_change();
});

$('#wifi-calendar').on('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    $('#calendar-dialog').modal({keyboard:false,backdrop:'static'}).modal('show');
    $('[name=alwayson-chk]').each(function() {
	if ($(this).val() == $('[name=alwayson]').val()) {
	    $(this).prop('checked', true);
	    return false;
	}
    });

    if ($('[name=alwayson]').val() == '0') {
	$('#extend-time').show();
	if ($('#extend-time-alert').data('extended')) {
	    $('#extend-time-alert').show();
	}
	$('#calendar-container').show();
    }
    else {
	$('#extend-time').hide();
	$('#extend-time-alert').hide();
	$('#calendar-container').hide();
    }

    $('#calendar-tabs a:first').tab('show');
    $('#calendar-tabs a:first').trigger('shown.bs.tab');
    adjustModalBackDrop();
});

function create_overlay(table, column) {
    var $tc = $('tr:eq(1) td:eq('+column+')', table);
    var $bc = $('tr:last td:last', table);
    $c = $('<div/>', {class: "ts-container"}).css({
	    position: 'absolute', 
	    top: $tc.position().top + table.position().top + parseInt(table.css('margin-top')) + 1, 
	    left:$tc.position().left + table.position().left + 1,
	    width:$tc.width(),
	    height: '1440px',
	    'background-color': 'transparent',
	    'z-index': 0
    })
    .data('day', column - 1);
    table.after($c);
}

$('#calendar-dialog a[data-toggle="tab"]').on('shown.bs.tab', function(e) {
    var active = e.target.hash;
    if (active == '#calendar-graphic-input') {
	$('.ts-container').remove();

	var $t = $('#graphic-calendar');
	if (!$t.is(':visible')) {
	    return;
	}

	for (var i = 1; i <= 7; i++) {
	    create_overlay($t, i);
	}

	var timeslots = [];
	$('#text-calendar tr:eq(1) textarea').each(function() {
	    var bands = [];
	    $(this).val().replace(/(\d?\d:\d?\d ?(?:am|pm)) ?- ?(\d?\d:\d?\d ?(?:am|pm))/g, function(s, p1, p2) {
		var lo = pcwrt.time2pixel(p1);
		var hi = pcwrt.time2pixel(p2);
		if (hi == 0) {
		    hi = $('.ts-container').height();
		}
		bands.push([lo, hi])
		return s;
	    });
	    timeslots.push(bands);
	});

	$('.ts-container')
	.sort(function (a, b) {
	    return $(a).data('day') - $(b).data('day');
	})
	.addRangeSelect('#5bc0de', function(v) {
	    return pcwrt.pixel2time(v, $('.ts-container').height());
	}, timeslots);
    }
});

$('#calendar-dialog a[data-toggle="tab"]').on('show.bs.tab', function(e) {
    var active = e.target.hash;
    if (active == '#calendar-text-input') {
	$('.ts-container').each(function() {
	    var bands = '';
	    $('.slider', $(this))
	    .sort(function(a, b) {
		return $(a).position().top - $(b).position().top;
	    })
	    .each(function() {
		var t = $(this).position().top + 10;
		var lo = pcwrt.pixel2time(t);
		if (lo.length < 8) { lo = '0'+lo; }
		var hi = pcwrt.pixel2time(t + $('.spacer', $(this)).height());
		if (hi.length < 8) { hi = '0'+hi; }
		var newslot = lo + ' - ' + hi;
		bands = bands ? bands + '\n' + newslot : newslot;
	    });
	    $('#text-calendar tr:eq(1) td:eq('+$(this).data('day')+') textarea').val(bands);
	});
    }
});

function copy_macfilter_to_other_bands($tab) {
    $tab.siblings().each(function() {
	$('[name=macfilter]', $(this)).val($('[name=macfilter]', $tab).val());
	$('.maclist-ul', $(this)).html($('.maclist-ul', $tab).html());
	macfilter_change($('select[name=macfilter]', $(this)));
    });
}

$('#wireless-settings>form>.nav-tabs').on('shown.bs.tab', 'a', function() {
    var idx = $(this).parent().index();
    var $tab = $('#wireless-settings>form>>.tab-pane:eq('+idx+')');
    if ($('.wireless-settings', $tab).is(':visible') || $('#wireless-update button[type="submit"]').data('calendar-updated')) {
        $('#wireless-update button[type="submit"]').show();
    }
    else {
        $('#wireless-update button[type="submit"]').hide();
    }
});

$('#wireless-settings>form>.nav-tabs').on('hide.bs.tab', 'a', function() {
    if (!$('#wireless-settings [name=onefilter]').prop('checked')) {
	return;
    }

    var $tab = $('#wireless-settings>form>.tab-content>.tab-pane:eq('+$(this).parent().index()+')');
    copy_macfilter_to_other_bands($tab);
});

$('#wireless-settings').on('click', '[name=onefilter]', function(e) {
    if ($(this).prop('checked')) {
	$('#wireless-settings [name=onefilter]').prop('checked', true);
    }
    else {
	$('#wireless-settings [name=onefilter]').prop('checked', false);
    }
});

$('#calendar-dialog button').on('click', function() {
    if ($(this).hasClass('save')) {
    	if ($('#calendar-graphic-input').is(':visible')) {
	    $('#calendar-tabs [href="#calendar-text-input"]').trigger('show.bs.tab');
	}

	$('[name=alwayson]').val($('[name=alwayson-chk]:checked').val());

	var schedule = [];
	$('#text-calendar tr:eq(1) textarea').each(function() {
	    schedule[$(this).parent().index()] = $(this).val();
	});
	$('#calendar-dialog').data('schedule', schedule);
	$('#wireless-update button[type="submit"]').data('calendar-updated', true).show();
    }
    $('#calendar-dialog').modal('hide');
});

function initialize_calendar() {
    var timeslots = [
	'12 <sup>am</sup>',
	'1 <sup>am</sup>',
	'2 <sup>am</sup>',
	'3 <sup>am</sup>',
	'4 <sup>am</sup>',
	'5 <sup>am</sup>',
	'6 <sup>am</sup>',
	'7 <sup>am</sup>',
	'8 <sup>am</sup>',
	'9 <sup>am</sup>',
	'10 <sup>am</sup>',
	'11 <sup>am</sup>',
	'12 <sup>pm</sup>',
	'1 <sup>pm</sup>',
	'2 <sup>pm</sup>',
	'3 <sup>pm</sup>',
	'4 <sup>pm</sup>',
	'5 <sup>pm</sup>',
	'6 <sup>pm</sup>',
	'7 <sup>pm</sup>',
	'8 <sup>pm</sup>',
	'9 <sup>pm</sup>',
	'10 <sup>pm</sup>',
	'11 <sup>pm</sup>'
    ];

    var $tbl = $('#graphic-calendar');
    for (var i = 0; i < timeslots.length; i++) {
	$('<tr><td rowspan="2">'+timeslots[i]+'</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>').appendTo($tbl);
	$('<tr class="odd"><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>').appendTo($tbl);
    }

    $('tr:first td:first', $tbl).css({'border-top': '1px solid transparent', 'border-left': '1px solid transparent'});

    $('td', $tbl).outerHeight(30);
    $('tr:first td', $tbl).outerHeight(51);
    $('tr:last td', $tbl).outerHeight(31);
    $('#text-calendar tr:first td').outerHeight(51);

    var schedule = [];
    if (fv.schedule && typeof(fv.schedule) == 'object') {
	$.each(fv.schedule, function(idx, v) {
	    $('#text-calendar tr:eq(1) td:eq('+idx+') textarea').val(v);
	    schedule[idx] = v;
	});
    }
    $('#calendar-dialog').data('schedule', schedule);

    if ($('#extend-time-alert').data('extended')) {
	$('#extend-time-alert').show();
    }
}

function add_options(e, opts) {
    $.each(opts, function(idx, opt) {
	e.append($('<option/>').attr('value', opt.value).text(opt.text));
    });
}

$(function() {
    /* clone first band wifi settings to second band */
    for (var i = 1; i < fv.devices.length; i++) {
	var p = $('#wireless-settings>form>.nav-tabs>li:first').clone();
	p.removeClass('active');
	$('#wireless-settings>form>.nav-tabs').append(p);

	var w = $('#wireless-settings>form>.tab-content>div:first').clone();
	w.removeClass('in active');
	$('#wireless-settings>form>.tab-content').append(w);
    }
    /* done cloning */

    if (fv.devices.length > 1) {
	$('#wireless-settings>form>.nav-tabs').show();
	$('#wireless-settings .onefilter').show();
    }

    var j2 = 0;
    $.each(fv.devices, function(idx, d) {
	var $tab = $('#wireless-settings>form')
	.find('>.nav-tabs>li:eq('+idx+') a')
	.attr('href', '#'+d.band.replace(/[^0-9a-zA-Z]/g, '-') + idx)
	.attr('aria-controls', d.band)
	.text(d.band)
	.end()
	.find('>.tab-content>.tab-pane:eq('+idx+')')
	.attr('id', d.band.replace(/[^0-9a-zA-Z]/g, '-') + idx);

	if (d.disabled) {
	    $('.enable-disable', $tab).addClass('alert-danger').removeClass('alert-success');
	    $('.wireless-status', $tab).text(window.msgs.disabled);
	    $('.enable-wireless', $tab).removeClass('hidden');
	}
	else {
	    $('.enable-disable', $tab).removeClass('alert-danger').addClass('alert-success');
	    $('.wireless-status', $tab).text(window.msgs.enabled);
	    $('.wifi-control-buttons', $tab).removeClass('hidden');
	    $('.wireless-settings', $tab).show();
	}

	$('.enable-wireless', $tab).on('click', function(e) {
	    e.preventDefault();
	    $tab.data('disabled', false);
	    $('.enable-disable', $tab).addClass('hidden');
	    $('.enable-alert', $tab).removeClass('hidden');
	    $('.wireless-settings', $tab).show();
	    $('#wireless-update button[type="submit"]').show();
	});

	$tab.data('name', d['.name']);
	$tab.data('disabled', d.disabled);

	$('.disable-wireless', $tab).on('click', function(e) {
	    e.preventDefault();
	    var $form = $(this).parents('form');
	    pcwrt.submit_form($form, { devname: $tab.data('name'), disabled: true }, function(r) {
		$('.wireless-status', $tab).text(msgs.disabled)
		.parent().removeClass('alert-success').addClass('alert-danger');
	       	$('.enable-wireless', $tab).removeClass('hidden');
	      	$('.wifi-control-buttons', $tab).addClass('hidden');
	     	$('.wireless-settings', $tab).hide();
	    	$('#wireless-update button[type="submit"]').hide();
		pcwrt.showOverlay($('#spinner'));
		$('<iframe/>', {src: r.reload_url+'?addr='+r.addr+'&page=settings%2Fwireless'}).appendTo('#reloader');
	    });
	});

	$tab.find('[for=channel-1]').attr('for', 'channel-'+idx);
	$tab.find('[id=channel-1]').attr('id', 'channel-'+idx);
	$tab.find('[for=bw-1]').attr('for', 'bw-'+idx);
	$tab.find('[id=bw-1]').attr('id', 'bw-'+idx);
	$tab.find('[for=txpower-1]').attr('for', 'txpower-'+idx);
	$tab.find('[id=txpower-1]').attr('id', 'txpower-'+idx);
	$tab.find('[for=macfilter-1]').attr('for', 'macfilter-'+idx);
	$tab.find('[id=macfilter-1]').attr('id', 'macfilter-'+idx);
	$tab.find('[for=macaddr-1]').attr('for', 'macaddr-'+idx);
	$tab.find('[id=macaddr-1]').attr('id', 'macaddr-'+idx);

	add_options($('[name=channel]', $tab), d.channels); 
	add_options($('[name=bw]', $tab), d.cwidths); 
	add_options($('[name=txpower]', $tab), d.txpowers); 
	$('[name=block_krack]', $tab).val(d.block_krack);
	$('[name=channel]', $tab).val(d.channel);
	$('[name=bw]', $tab).val(d.bw);
	$('[name=txpower]', $tab).val(d.txpower);

	$('select[name=macfilter]', $tab).val(d.macfilter);
	if (d.onefilter == '0') {
	    $('[name=onefilter]', $tab).prop('checked', false);
	}
	else {
	    $('[name=onefilter]', $tab).prop('checked', true);
	}

	$.each(d.maclist, function(i2, m) {
	    var mac = m.mac;
	    if (m.hostname) {
		mac = mac + ' <span style="text-transform:none;">('+m.hostname+')</span>'; 
	    }
	    $('.maclist-ul', $tab).append('<li class="option-list mac-addr"><span class="list-remove pull-right">&nbsp;</span>' + mac + '</li>');
	});
	macfilter_change($('select[name=macfilter]', $tab));

	d.interfaces.sort(function(a, b) {
	    return a.id - b.id;
	});
	$.each(d.interfaces, function(j, ifc) {
	    var $nt, $ifc;
	    if (j > 0) {
		var $nt = $('.nav-tabs>li:first', $tab).clone();
		$nt.removeClass('active');
		$('a', $nt).attr('href', '#dev-'+idx+'-ifc-'+j).attr('aria-controls', ifc.display_name).data('vlanid', ifc.id).html(ifc.display_name + '<div>&cross;</div>');
		$('.nav-tabs', $tab).append($nt);
		$ifc = $('.tab-content>div:first', $tab).clone();
		$ifc.removeClass('in active');
		$('.tab-content', $tab).append($ifc);
	    }
	    else {
		$nt = $('.nav-tabs>li:first', $tab);
		$('a', $nt).attr('href', '#dev-'+idx+'-ifc-'+j).attr('aria-controls', ifc.display_name).data('vlanid', ifc.id).text(ifc.display_name);
		$ifc = $('.tab-content>div:first', $tab);
		add_options($('[name=encryption]', $ifc), d.encryptions);
		add_options($('[name=cipher]', $ifc), d.ciphers);
	    }

	    $ifc.data('vlanid', ifc.id);
	    $ifc.attr('id', 'dev-'+idx+'-ifc-'+j);
	    $ifc.find('[for=ssid-1]').attr('for', 'ssid-'+j2);
	    $ifc.find('[id=ssid-1]').attr('id', 'ssid-'+j2);
	    $ifc.find('[for=encryption-1]').attr('for', 'encryption-'+j2);
	    $ifc.find('[id=encryption-1]').attr('id', 'encryption-'+j2);
	    $ifc.find('[for=cipher-1]').attr('for', 'cipher-'+j2);
	    $ifc.find('[id=cipher-1]').attr('id', 'cipher-'+j2);
	    $ifc.find('[for=key-1]').attr('for', 'key-'+j2);
	    $ifc.find('[id=key-1]').attr('id', 'key-'+j2);
	    $ifc.find('.form-control-error').remove().end().find('.form-group').removeClass('has-error');

	    $('[name=hidessid]', $ifc).val(ifc.hidessid);
	    $('[name=isolate]', $ifc).val(ifc.isolate);
	    $('[name=ssid]', $ifc).val(ifc.ssid);
	    $('[name=encryption]', $ifc).val(ifc.encryption);
	    $('[name=cipher]', $ifc).val(ifc.cipher);
	    $('[name=key]', $ifc).val(ifc.key);

	    encryption_change($('select[name=encryption]', $ifc));
	    j2++;
	});

	if ($('.nav-tabs>li', $tab).length > 4) {
	    $('.add-wifi a', $tab).addClass('disabled');
	}
    });

    if (!fv.devices[0].disabled) {
	$('#wireless-update button[type="submit"]').show();
    }

    $('label.required').add_required_mark(window.msgs.required);
    $('label.control-label[data-hint]').init_hint();
    $('input[type=password].reveal').reveal();

    $('select[name=macfilter]').on('change', function() {
	macfilter_change($(this));
    });

    $('select[name=encryption]').on('change', function() {
	encryption_change($(this));
    });

    $('select').makecombo();

    $('.add-wifi').on('click', function(e) {
	e.preventDefault();
	if ($('a', $(this)).hasClass('disabled')) {
	    return;
	}

	$('#add-wifi-dialog .list-group').empty();

	var $el = $(this);
	var networks = [];
	$.each(fv.vlans, function(i, vlan) {
	    var add = true;
	    $el.siblings().each(function() {
		if (vlan.value == $('a', $(this)).data('vlanid')) {
		    add = false;
		    return false;
		}
	    });

	    if (add) {
		networks.push(vlan);
	    }
	});

	$.each(networks, function(i, v) {
	    $('#add-wifi-dialog .list-group').append(
		'<li class="list-group-item clickable" data-id="'+v.value+'">'+v.text+'</li>'
	    );
	});

	var d = $(this).parents('.tab-pane:last').index();
	$('#add-wifi-dialog').data('device_idx', d).modal('show');
    });

    $('#add-wifi-dialog').on('click', '.list-group-item', function() {
	var network = null;
	var id = $(this).data('id');
	$.each(fv.vlans, function(i, vlan) {
	    if (vlan.value == id) {
		network = vlan;
		return false;
	    }
	});

	if (network) {
	    var dev_idx = $('#add-wifi-dialog').data('device_idx');
	    var d = fv.devices[dev_idx];
	    var $tab = $('#wireless-settings>form>.tab-content>.tab-pane:eq('+dev_idx+')');
	    var $nt = $('.nav-tabs>li:first', $tab).clone();
	    var j = $('.nav-tabs', $tab).data('j');
	    if (j == null) {
		j = $('.nav-tabs', $tab).children().length;
	    }
	    $nt.removeClass('active');
	    var $ifc = $('.tab-content>div:first', $tab).clone();
	    $ifc.removeClass('in active');

	    $('a', $nt).attr('href', '#dev-'+dev_idx+'-ifc-'+j).attr('aria-controls', network.text).data('vlanid', network.value).html(network.text + '<div>&cross;</div>');
	    $ifc.data('vlanid', network.value);
	    $ifc.attr('id', 'dev-'+dev_idx+'-ifc-'+j);
	    var idx = $('[for^=ssid-]', $ifc).attr('for').replace(/^ssid-/, '');
	    $ifc.find('[for=ssid-'+idx+']').attr('for', 'ssid-'+dev_idx+'-'+j);
	    $ifc.find('[id=ssid-'+idx+']').attr('id', 'ssid-'+dev_idx+'-'+j);
	    $ifc.find('[for=encryption-'+idx+']').attr('for', 'encryption-'+dev_idx+'-'+j);
	    $ifc.find('[id=encryption-'+idx+']').attr('id', 'encryption-'+dev_idx+'-'+j);
	    $ifc.find('[for=cipher-'+idx+']').attr('for', 'cipher-'+dev_idx+'-'+j);
	    $ifc.find('[id=cipher-'+idx+']').attr('id', 'cipher-'+dev_idx+'-'+j);
	    $ifc.find('[for=key-'+idx+']').attr('for', 'key-'+dev_idx+'-'+j);
	    $ifc.find('[id=key-'+idx+']').attr('id', 'key-'+dev_idx+'-'+j);
	    $ifc.find('[id=key-'+idx+'-clone]').attr('id', 'key-'+dev_idx+'-'+j+'-clone');
	    $('.nav-tabs', $tab).data('j', j + 1);
	    $ifc.find('.combo-group').remove();

	    $('[name=hidessid]', $ifc).val('');
	    $('[name=isolate]', $ifc).val('');
	    $('[name=ssid]', $ifc).val('');
	    $('[name=encryption]', $ifc).makecombo().val('none');
	    $('[name=cipher]', $ifc).makecombo().val('auto');
	    $('[name=key]', $ifc).val('');
	    encryption_change($('select[name=encryption]', $ifc));

	    $('select[name=encryption]', $ifc).on('selection.change', function() {
		encryption_change($(this));
	    });

	    $('input[type=password].reveal', $ifc).reveal();

	    $('.nav-tabs', $tab).append($nt);
	    $('.tab-content', $tab).append($ifc);

	    $('a', $nt).tab('show');
	    if ($('.nav-tabs>li', $tab).length > 4) {
		$('.add-wifi a', $tab).addClass('disabled');
	    }
	}

	$('#add-wifi-dialog').modal('hide');
    });

    $('.wifi-networks').on('click', '.nav-tabs li div', function() {
	var $a = $(this).parent();
	var $c = $a.parents('.nav-tabs:first');
	var name = $a.contents().filter(function() {
			return this.nodeType == 3;
		   }).text();
	pcwrt.confirm_action(window.msgs.delete_wifi_title,
	    window.msgs.delete_wifi_confirm + ' "' + name + '"?', function() {
	    $($a.attr('href')).remove();
	    $a.parent().remove();
	    $('a:first', $c).tab('show');
	    $('.add-wifi a', $c).removeClass('disabled');
	});
    });

    $('.maclist-div span.list-find').on('click', function() {
    	var $c = $(this).parent().parent();
	$c.removeClass('has-error')
	.find('.form-control-error').remove();
	pcwrt.submit_form($("#get-assocmacs"), [], function(r) {
	    var ext = [];
	    $.each(r.assocmacs, function(i, v) {
		var found = false;
		$('.maclist-ul li', $c).each(function() {
		    if ($(this).text().replace(/\(.*\)/, '').trim().toUpperCase() == v.mac.toUpperCase()) {
			found = true;
			return false;
		    }
		});

		if (!found) {
		    ext.push(v);
		}
	    });

	    if (ext.length == 0) {
		$('#maclist-tbl').hide();
		$('#maclist-empty').show();
		$('#maclist-modal button[type=submit]').hide();
	    }
	    else {
		ext.sort(function(a, b) {return (""+a.name).toUpperCase() > (""+b.name).toUpperCase()?1:-1;});
		$('#maclist-tbl').show();
		$('#maclist-empty').hide();
		$('#maclist-tbl tr').not(':first').remove();
		$.each(ext, function(i, v) {
		    $('#maclist-tbl').append('<tr><td><input type="checkbox"></td><td>'
		    +v.mac.toUpperCase()+'</td><td>'+v.name+'</td></tr>');
		});
		$('#maclist-tbl input').prop('checked', false);
		$('#maclist-modal button[type=submit]').show();
	    }
	    $('#maclist-modal').modal('show');
	}, null, true);
    });

    $('#maclist-tbl').on('click', 'input', function(e) {
	var tr = $(this).parents('tr:first');
	if (tr.is(':first-child')) {
	    if ($(this).prop('checked')) {
		$('input', tr.siblings()).prop('checked', true);
	    }
	    else {
		$('input', tr.siblings()).prop('checked', false);
	    }
	}
	else {
	    if (!$(this).prop('checked')) {
		$('input', tr.siblings(':first')).prop('checked', false);
	    }
	    else {
		var all_checked = true;
		tr.siblings().not(':first').each(function() {
		    if (!$('input', $(this)).prop('checked')) {
			all_checked = false;
			return false;
		    }
		});

		if (all_checked) {
		    $('input', tr.siblings(':first')).prop('checked', true);
		}
	    }
	}
    });

    $('#maclist-modal button[type=submit]').on('click', function(e) {
	e.preventDefault();
	$('#maclist-tbl tr').not(':first').each(function() {
	    if ($('input', $(this)).prop('checked')) {
		var mac = $('td:eq(1)', $(this)).text().trim();
		var hostname = $('td:eq(2)', $(this)).text().trim();
		if (hostname != '') {
		    mac = mac + ' <span style="text-transform:none;">(' + hostname + ')</span>';
		}

		$('.maclist-ul:visible')
		.append('<li class="option-list mac-addr"><span class="list-remove pull-right">&nbsp;</span>'
		+ mac + '</li>');
	    }
	});
	$('#maclist-modal').modal('hide');
    });

    $('.maclist-div span.list-add').on('click', function() {
    	var $c = $(this).parent().parent();
	$c.removeClass('has-error')
	.find('.form-control-error').remove();

	var mac = $(this).prev().prev().val();
	if (!pcwrt.is_valid_macaddr(mac)) {
	    $c.addClass('has-error')
	    .append('<p class="form-control-error">'+window.msgs.invalid_mac_addr+'.</p>');
	    return;
	}

	$('.maclist-ul li').each(function() {
	    if ($(this).text().replace(/\(.*\)/, '').trim().toUpperCase() == mac.toUpperCase()) {
		mac = null;
		return false;
	    }
	});

	if (!mac) {
	    $c.addClass('has-error')
	    .append('<p class="form-control-error">'+window.msgs.mac_addr_already_added+'.</p>');
	    return;
	}

	$(this).parent().prev().append(
	'<li class="option-list mac-addr"><span class="list-remove pull-right">&nbsp;</span>'
	+mac+'</li>');

	$(this).prev().prev().val('');
    });

    $('.maclist-div').on('click', 'span.list-remove', function() {
	$(this).parent().remove();
    });

    $('#wireless-update button[type="submit"]').on('click', function(e) {
	e.preventDefault();

	$('#wireless-settings>form>.tab-content>.tab-pane').each(function() {
	    $(this).data('haserror', false);
	    $('.tab-pane', $(this)).each(function() {
		$(this).data('haserror', false);
	    });
	});

	var $form = $(this).parents('form');
	pcwrt.submit_form($form, function() {
	    var data = [];
	    data.push({
		name: 'alwayson',
		value: $('input[name=alwayson]').val()
	    });

	    if ($('#calendar-dialog').data('schedule')) {
		data.push({
		    name: 'schedule',
		    value: JSON.stringify($('#calendar-dialog').data('schedule'))
		});
	    }

	    if ($('#wireless-settings [name=onefilter]:visible').prop('checked')) {
		copy_macfilter_to_other_bands($('#wireless-settings>form>.tab-content>.tab-pane:visible'));
	    }

	    var devs = [];
	    $('#wireless-settings>form>.tab-content>.tab-pane').each(function() {
		var dev = {};
		dev['.name'] = $(this).data('name');
     		dev.disabled = $(this).data('disabled');
    		if (dev.disabled) {
   		    devs.push(dev);
  		    return;
 		}

		dev.block_krack= $('[name=block_krack]', $(this)).prop('checked') ? '1' : '0';
		dev.channel = $('[name=channel]', $(this)).val();
		dev.bw = $('[name=bw]', $(this)).val();
		dev.txpower = $('[name=txpower]', $(this)).val();
		dev.onefilter = $('[name=onefilter]', $(this)).prop('checked') ? '1' : '0';
		dev.macfilter = $('[name=macfilter]', $(this)).val();
		dev.maclist = [];
		$('.maclist-ul li', $(this)).each(function() {
		    dev.maclist.push($(this).text().replace(/\(.*\)/, '').trim());
		});

		var ifaces = [];
		$('.wifi-networks .tab-pane', $(this)).each(function() {
		    var iface = {};
		    iface.vlanid = $(this).data('vlanid');
		    iface.hidessid = $('[name=hidessid]', $(this)).prop('checked') ? '1' : '0';
		    iface.isolate = $('[name=isolate]', $(this)).prop('checked') ? '1' : '0';
		    iface.ssid = $('[name=ssid]', $(this)).val();
		    iface.encryption = $('[name=encryption]', $(this)).val();
		    iface.cipher = $('[name=cipher]', $(this)).val();
		    iface.key = $('[name=key]', $(this)).val();
		    ifaces.push(iface);
		});
		dev.ifaces = ifaces;
		devs.push(dev);
	    });

	    data.push({
		name: 'devices',
		value: JSON.stringify(devs)
	    });

	    return data;
	},
	{
	    error: function(r) {
		$.each(r.message, function(idx, msg) {
		    var $tab = $('#wireless-settings>form>.tab-content>.tab-pane:eq('+idx+')');
		    $.each(msg.errs, function(name, err) {
			var input = $(':input[name="'+name+'"]', $tab);
			if (input.parent().hasClass('input-group')) {
			    input = input.parent();
			}
			input.parent()
			.addClass('has-error')
			.append('<p class="form-control-error">'+err+'</p>');
			$tab.data('haserror', true);
		    });

		    $.each(msg.ifaces, function(idx2, errs) {
			var $ifc = $('.tab-content>.tab-pane:eq('+idx2+')', $tab);
			$.each(errs, function(name, err) {
			    var input = $(':input[name="'+name+'"]', $ifc);
			    if (input.parent().hasClass('input-group')) {
				input = input.parent();
			    }
			    input.parent()
			    .addClass('has-error')
			    .append('<p class="form-control-error">'+err+'</p>');
			    $ifc.data('haserror', true);
			    $tab.data('haserror', true);
			});
		    });
		});

		$('#wireless-settings>form>.nav-tabs a').each(function() {
		    var $tab = $($(this).attr('href'));
		    if ($tab.data('haserror')) {
			$('.nav-tabs a', $tab).each(function() {
			    var sel = $(this).attr('href');
			    if (sel) { sel = sel.trim(); }
			    if (sel && sel != '#') {
				var $ifc = $($(this).attr('href'));
				if ($ifc.data('haserror')) {
				    $(this).tab('show');
				    return false;
				}
			    }
			});
			$(this).tab('show');
			return false;
		    }
		});
	    },

	    success: function(r) {
		$('#wireless-status').text(msgs.enabled)
		.parent().removeClass('alert-danger').addClass('alert-success');
		$('#enable-wireless').addClass('hidden');
		$('#enable-alert').addClass('hidden');
		pcwrt.showOverlay($('#spinner'));
		$('<iframe/>', {src: r.reload_url+'?addr='+r.addr+'&page=settings%2Fwireless'}).appendTo('#reloader');
	    }
	})
    });

    $('[name=alwayson]').val(fv.alwayson);
    initialize_calendar();

    if (/applyreboot/.test(document.referrer)) {
	$('#status-modal .modal-title').text(window.msgs.success);
	$('#status-modal .modal-body p').text(window.msgs.apply_success);
	$('#status-modal').modal('show');
    }
});
