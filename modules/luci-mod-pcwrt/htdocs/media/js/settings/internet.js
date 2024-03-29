function switch_protocol() {
    var sel = $('#protosel').val();
    $('.proto-option').each(function() {
	if (this.id == 'proto-'+sel) {
	    $(this)
	    .removeClass('hidden')
	    .find('input[name="proto"]')
	    .val(sel);
	}
	else {
	    $(this).addClass('hidden');
	}
    });
}

function switch_peerdns(c) {
    if ($(c).prop('checked')) {
      	$(c).parent().next().slideDown();
    }
    else {
      	$(c).parent().next().slideUp();
    }
}

function send_update($form) {
    pcwrt.submit_form($form, $form.serialize(), function(r) {
	pcwrt.showOverlay($('#spinner'));
	$('<iframe/>', {src: r.reload_url+'?addr='+r.addr+'&page=settings%2Finternet'}).appendTo('#reloader');
    });
}

$('[name=macaddr]').on('change', function() {
    $(this).parent().removeClass('has-error').end().next('.form-control-error').remove();
    $(this).val($(this).val().replace(/[^0-9a-f]/ig, '').replace(/(..)\B/g, "$1:"));
    if ($(this).val().trim() != '' && $(this).val().length != 17) {
       $(this).parent().addClass('has-error').end()
       .after('<p class="form-control-error">' + window.msgs.invalid_macaddr + '</p>');
    }
});

$(function() {
    $('label.required').add_required_mark(window.msgs.required);
    $('label.control-label[data-hint]').init_hint();
    $('input[data-units]').makeunit();
    $('select').makecombo();

    $('#dhcp-macrefresh').on('unit.change', function(e, u) {
	$(this).parent().parent().removeClass('has-error').find('.form-control-error').remove();
	if (u == 'o') {
	    $(this).prop('value', '').prop('disabled', true);
	}
	else {
	    $(this).prop('disabled', false);
	}
    });

    pcwrt.populate_forms();
    switch_protocol();
    $('[name=peerdns]').each(function() {
	switch_peerdns(this);
    });

    $('#protosel').on('change', function() {
	switch_protocol();
    });

    $('[name=peerdns]').each(function() {
    	$(this).on('click', function() {
	    switch_peerdns(this);
    	});
    });

    $('button[type="submit"]').on('click', function (e) {
	e.preventDefault();

	var $form = $(this).parents('form');
	send_update($form);
    });
});
