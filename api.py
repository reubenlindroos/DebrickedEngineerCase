import data_handler
import flask
from flask import request

app = flask.Flask(__name__)
app.config["DEBUG"] = True


# CPE endpoint with vendor and product variables

@app.route('/cpe', methods=['GET'])
def cpe_filter():
    """
    using localhost:5000/cpe?vendor=xx&product=yy syntax
    as it is apparently more flexible (multiple queries
    at once for instance)

    at least one of these needs to be defined, or it
    will return 404.

    :param vendor: (str) vendor
    :param product: (str) product
    :return: list of CVEs
    """
    query_parameters = request.args
    vendor = query_parameters.get('vendor')
    product = query_parameters.get('product')
    dh = data_handler.DataHandler()

    if not (vendor or product):
        return page_not_found(404)

    return dh.querry_cpe(vendor, product)

# CVE end point

@app.route('/cve', methods=['GET'])
def cve_filter():
    query_parameters = request.args
    cve_id = query_parameters.get('id')
    dh = data_handler.DataHandler()
    if not cve_id:
        return page_not_found(404)
    return dh.querry_cve(cve_id)

@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404
app.run()