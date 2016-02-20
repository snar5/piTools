$(document).ready(function () {
	        $("#btnDetails").click(function() {
			netName = document.getElementById('netName').value;
			netChannel = document.getElementById('netChannel').value;
			netEssid = document.getElementById('netEssid').value;
			$("#tbl_status").empty();
			$.ajax({
				type:'POST',
				url: '/captureDetails',
				data:{'essid':netEssid, 'channel':netChannel,'name':netName},
				success:function(results){
					//console.log(results);

					$("#tbl_status").append("<tr><td>Results</td></tr>");
					$("#tbl_status").append("<tr><td>" + results + "</td></tr>");
				}


	
				});
					console.log(netName,netChannel,netEssid);
			});
});
