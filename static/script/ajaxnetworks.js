$(document).ready(function() {	
	
	$("#btnShowNetwork").click(function() {
		get_wifilist();
	});

	function get_wifilist(){
		jQuery.ajax({ 
			type: "POST",
			dataType : "json",      
			success: function(results){
				setTimeout(function(){get_wifilist();},10000);
				$("#tbl_wifi").empty();
				$.each(results,function(index,result){
					// console.log(result.power);
					$("#tbl_wifi").append("<tr><td height='50' width='350'><b> SSID:</b> " + result.name + "<br><b>  ESSID:</b> " + result.essid + " </td><td width='150'>Power:" + result.power + "</td><td>Channel: " + result.channel + "</td><td><button class='btn btn-primary'>Capture</button></td></tr>");})
			}
			});
	} //End of getwifilist

}); // 
