param(
    #region Standard Parameters
        #This object contains the message body object converted from JSON if any was passed
        [parameter(Mandatory=$false)]
        [object]$InputObject,

        #This object contains the actual HTTP request that was received
        [parameter(Mandatory=$false)]
        [object]$Request,

        #Default status code
        [parameter(Mandatory=$false)]
        [validateset("Success","FileNotFound","ServiceUnavailable","InternalError","AccessDenied","BadRequest","Unauthorized","UnexpectedError","Teapot","UnsupportedMediaType","MovedPermanently","Found","TemporaryRedirect","PermanentRedirect","Forbidden")]
        [string]$status_code = "Success",

        #Default content type
        [parameter(Mandatory=$false)]
        [validateset("text/html","application/json","text/xml","text/csv")]
        [string]$content_type="text/html",

         #Default content type  Example might be @{"Location" = "/some/other/page.htm"}
        [parameter(Mandatory=$false)]
        [hashtable]$additional_headers,
    #endregion
    
    [parameter(Mandatory=$false)]
    [string]$raw
)

Try
{
    
    if($raw -eq "true")
    {
        $output= get-process | ConvertTo-json
        $content_type="application/json"        
    }
    else
    {
        $output= get-process | ConvertTo-Html -CssUri /includes/css/bootstrap.css
        $content_type="text/html"
    }

    $status_code="Success"
}
Catch
{
    $status_code="InternalError"
    $output = "Internal error."
}

$return=@{
status=$status_code
output=$output
content_type=$content_type
header=$additional_headers
}
return $return
