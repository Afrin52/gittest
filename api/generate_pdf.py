# from django.utils.functional import keep_lazy
# import pydf
# import os
# from django.conf import settings
# from django.template.loader import get_template


# class GeneratePDF:

#     def __init__(self, **kwargs):
#         self.context = kwargs.get("context", None)
#         self.type = kwargs.get("type", None)
#         if self.type == "order":
#             self.template_name = "order.html"
#         elif self.type == "delivery":
#             self.template_name = "delivery.html"

#     def __call__(self):
#         return self.generate_pdf()

#     def generate_pdf(self):
#         print("gen pdf")
#         context = self.context
#         template = get_template(self.template_name)
#         html_string = template.render(context)
#         pdf = pydf.generate_pdf(html_string)
#         return pdf