/**
 * Add JavaScript confirmation to the User Delete button
 */
jQuery(function(){
    jQuery('#usrmgr__del').click(function(){
        return confirm(LANG.del_confirm);
    });
});

function twofactor_action(module, request, data, callback) {
	jQuery.post(
		DOKU_BASE + 'lib/exe/ajax.php',
		{
			call: 'plugin_twofactor', 
			mod: module,
			req: request,
			data: JSON.stringify(data)
		},
		callback,
		'json'
	);
}
