#pragma checksum "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "a3c0cd8f1c38638defb12cffdfa0d4b331e556a1"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Areas_Manage_Views_Teacher_Detail), @"mvc.1.0.view", @"/Areas/Manage/Views/Teacher/Detail.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 2 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\_ViewImports.cshtml"
using EduHome.Model;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\_ViewImports.cshtml"
using EduHome.Dal;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\_ViewImports.cshtml"
using EduHome.Interfaces;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\_ViewImports.cshtml"
using EduHome.Areas.ViewModels;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"a3c0cd8f1c38638defb12cffdfa0d4b331e556a1", @"/Areas/Manage/Views/Teacher/Detail.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"2e95a9f5c220abfa60b824d51b14f6a60e08c947", @"/Areas/Manage/Views/_ViewImports.cshtml")]
    public class Areas_Manage_Views_Teacher_Detail : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<Teacher>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("width", new global::Microsoft.AspNetCore.Html.HtmlString("400"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("alt", new global::Microsoft.AspNetCore.Html.HtmlString("Alternate Text"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString("btn btn-dark"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "update", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "Index", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        #pragma warning restore 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
#nullable restore
#line 3 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
  
    ViewData["Title"] = "Detail";

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n\r\n\r\n<div>\r\n    <h4>Teacher Detail</h4>\r\n    <hr />\r\n    <dl class=\"dl-horizontal\">\r\n        <dt>\r\n            ");
#nullable restore
#line 14 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.FullName));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 17 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.FullName));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 20 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Image));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <td>\r\n            ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("img", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "a3c0cd8f1c38638defb12cffdfa0d4b331e556a17082", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
            BeginAddHtmlAttributeValues(__tagHelperExecutionContext, "src", 2, global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            AddHtmlAttributeValue("", 451, "~/assets/img/teacher/", 451, 21, true);
#nullable restore
#line 23 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
AddHtmlAttributeValue("", 472, Model.Image, 472, 12, false);

#line default
#line hidden
#nullable disable
            EndAddHtmlAttributeValues(__tagHelperExecutionContext);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n        </td>\r\n        <dt>\r\n            ");
#nullable restore
#line 26 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.About));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n");
#nullable restore
#line 29 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
             if (Model.About.Length > 100)
            {
                

#line default
#line hidden
#nullable disable
#nullable restore
#line 31 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
           Write(Model.About.Substring(0, 100));

#line default
#line hidden
#nullable disable
#nullable restore
#line 31 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
                                              
            }
            else
            {
                

#line default
#line hidden
#nullable disable
#nullable restore
#line 35 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
           Write(Html.DisplayFor(model => model.About));

#line default
#line hidden
#nullable disable
#nullable restore
#line 35 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
                                                      
            }

#line default
#line hidden
#nullable disable
            WriteLiteral("        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 39 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Degree));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 42 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Degree));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 45 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Experience));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 48 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Experience));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 51 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Faculty));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 54 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Faculty));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 57 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Email));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 60 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Email));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 63 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Phone));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 66 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Phone));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 69 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Skype));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 72 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Skype));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 75 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.Fblink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 78 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.Fblink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 81 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.PinttLink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 84 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.PinttLink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 87 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.VimeoLink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 90 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.VimeoLink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 93 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.TwtLink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 96 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.TwtLink));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n        <dt>\r\n            ");
#nullable restore
#line 99 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayNameFor(model => model.TeacherPosition));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dt>\r\n        <dd>\r\n            ");
#nullable restore
#line 102 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
       Write(Html.DisplayFor(model => model.TeacherPosition.Name));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n        </dd>\r\n</div>\r\n<div>\r\n    ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("a", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a3c0cd8f1c38638defb12cffdfa0d4b331e556a118537", async() => {
                WriteLiteral("Update");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_2);
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.Action = (string)__tagHelperAttribute_3.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_3);
            if (__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues == null)
            {
                throw new InvalidOperationException(InvalidTagHelperIndexerAssignment("asp-route-id", "Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper", "RouteValues"));
            }
            BeginWriteTagHelperAttribute();
#nullable restore
#line 106 "C:\Users\ROG\Desktop\P228_ASP_08-12-2022_BackEndTehmplate-main\EduHomeBackFinal-master\EduHome\Areas\Manage\Views\Teacher\Detail.cshtml"
                                                  WriteLiteral(Model.Id);

#line default
#line hidden
#nullable disable
            __tagHelperStringValueBuffer = EndWriteTagHelperAttribute();
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["id"] = __tagHelperStringValueBuffer;
            __tagHelperExecutionContext.AddTagHelperAttribute("asp-route-id", __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.RouteValues["id"], global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral(" |\r\n    ");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("a", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a3c0cd8f1c38638defb12cffdfa0d4b331e556a120845", async() => {
                WriteLiteral("Back to List");
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.AnchorTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_2);
            __Microsoft_AspNetCore_Mvc_TagHelpers_AnchorTagHelper.Action = (string)__tagHelperAttribute_4.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_4);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n</div>\r\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Teacher> Html { get; private set; }
    }
}
#pragma warning restore 1591
