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
				//console.log("wifi_list called"); for debug
				$("#tbl_wifi").empty();
				$.each(results,function(index, network){
					$("#tbl_wifi").append("<tr><td><b> SSID:</b> " + network + "<br><b>  ESSID:</b> " + index + " </td><td><button class='btn btn-primary'>Capture</button></td></tr>");})
			}
			});
	} //End of getwifilist

}); // 
