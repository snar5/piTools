$(document).ready(function () {	
		get_wifilist();
});
	$("btnCapture").click(function() {
		capture();
});
	


function apDetail(wifiname,channel,essid){
		window.location = "/apDetail?name=" + wifiname + "&channel=" + channel + "&essid=" + essid;
		}


function get_wifilist(){
	jQuery.ajax({ 
		type: "POST",
		dataType : "json",      
		success: function(results){
			setTimeout(function(){get_wifilist();},30000);
			if (results) {
			//console.log(results);
			$("#tbl_wifi").empty();
			$("#tbl_clients").empty();
			$("#tbl_wifi").append("<thead><tr><th>Network ID</th><th>Power</th><th>Channel</th><th>Data</th><th>Encryption</th><th>Client(s)</th></tr></thead>")
			$.each(results,function(index,result){
			var clientlist = ''
			var count = 0 
			$.each(result.clients, function(index,client){ 
				clientlist = clientlist + "<br>" + client;
			 count +=1});
			 
			console.log(count);
			var networkname = result.name + "\"," + result.channel + ",\"" + result.essid
			var networkname = "\"" + networkname + "\"";
			$("#tbl_wifi").append("<tr><td height='50' width='150'>SSID:<b><a href='#' onclick='apDetail(" + networkname + ")'> " + result.name + "</a></b><br>ESSID: " + result.essid + "</td><td width='150'>" + result.power + "</td><td width='150'>" + result.channel + "</td><td width='150'><b> " + result.data + "</b></td><td width='150'>" + result.enc + "</td><td width='150'> " + clientlist + "</td></tr>");})
			$("#tbl_wifi").tablesorter(); // {sortList: [[1,0]]}); //sortable table
			} else { 
			$("#tbl_wifi").append("<tr><td><img src='/static/images/ajax-loader.gif' width=40; height=40;> Waiting for networks....</td></tr>");
                        }
	
			}
			});
	} //End of getwifilist


