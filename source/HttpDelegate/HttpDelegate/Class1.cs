using System;
using System.Net;
using System.Xml;
using System.Diagnostics;
using System.Text.RegularExpressions;

public delegate System.Net.AuthenticationSchemes ClientAuthDelegate(string authtype);

public class CustomAuth
{
    public CustomAuth() { }
    public static String DocumentPath { get; set; }
    public static void SetDocumentPath(String newPath)
    {
        DocumentPath = newPath;
    }
    public static System.Net.AuthenticationSchemes ClientAuth(HttpListenerRequest request)
    {        
        Uri raw_uri = new Uri(request.Url.ToString());
        string uri_stem;
        string pattern = @"^\/\w+\.\w+$";
        Debug.WriteLine("Pattern match" + Regex.IsMatch(raw_uri.LocalPath, pattern));
        if ((raw_uri.LocalPath == "/") || (Regex.IsMatch(raw_uri.LocalPath,pattern)))
        {
            uri_stem = "/";
        }
        else
        {
            uri_stem = raw_uri.Segments[1];
        }
        string xpath_query = String.Concat("//virtualdirectory[(@uri='", uri_stem.ToLower(), "')]");


        XmlDocument myDoc = new XmlDocument();        
        myDoc.Load(DocumentPath);
        XmlElement root = myDoc.DocumentElement;
        XmlNode route = null;
        System.Net.AuthenticationSchemes retVal = AuthenticationSchemes.None;
        string auth = string.Empty;
        string message = string.Empty;
        try
        {
            route = root.SelectSingleNode(xpath_query);
           auth = route.Attributes["auth"].Value.ToLower();
            switch (auth)
            {
                case "anonymous":
                    retVal = AuthenticationSchemes.Anonymous;
                    Debug.WriteLine("Auth scheme=Anonymous /" + auth);
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    break;
                case "ntlm":
                    Debug.WriteLine("Auth scheme=Ntlm");
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    retVal = AuthenticationSchemes.Ntlm;
                    break;
                case "negotiate":
                    Debug.WriteLine("Auth scheme=Negotiate");
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    retVal = AuthenticationSchemes.Negotiate;
                    break;
                case "basic":
                    Debug.WriteLine("Auth scheme=Basic");
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    retVal = AuthenticationSchemes.Basic;
                    break;
                case "digest":
                    Debug.WriteLine("Auth scheme=Digest");
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    retVal = AuthenticationSchemes.Digest;
                    break;
                case "integratedwindowsauthentication":
                    Debug.WriteLine("Auth scheme=IWA");
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    retVal = AuthenticationSchemes.IntegratedWindowsAuthentication;
                    break;
                default:
                    Debug.WriteLine("Auth scheme=None");
                    Debug.WriteLine("Route " + route.Attributes["name"].Value.ToLower());
                    retVal = AuthenticationSchemes.None;
                    break;
            }
        }
        catch (Exception)
        {

            retVal = AuthenticationSchemes.None;
        }
        return retVal;


    }
}
