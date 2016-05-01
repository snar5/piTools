$(document).ready(function() {
		scanner_status();
});

function scanner_status(){
	$.ajax({
		type:"POST",
		url: "/scannerstatus",
		dataType : "json",
		success: function(results){
			setTimeout(function(){scanner_status();},5000);
			console.log(results);
			if (results == 0) { 
				$("#scanner").html('Scanner running');
			} else { $("#scanner").html('Scanner not running')};
			}})};
