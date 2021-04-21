from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Float, ForeignKey, and_
from sqlalchemy.orm import sessionmaker, relationship

import cpe
import json
import subprocess
import argparse
import os
import sys

Base = declarative_base()

class CVE(Base):
    __tablename__ = 'cve_table'
    id = Column(String, primary_key=True)
    desc = Column(String)
    pub_date = Column(String)
    last_mod_date = Column(String)
    cpe = relationship('CPE', secondary='link')
    score = Column(Float)

    def __repr__(self):
        lst = []
        lst.append('<CVE(')
        lst.append('id=' + self.id)
        lst.append(')>')
        return ''.join(lst)

class CPE(Base):
    __tablename__ = 'cpe_table'
    id = Column(String, primary_key=True)
    product = Column(String)
    vendor = Column(String)
    cve_lst = relationship('CVE', secondary='link')

    def __repr__(self):
        lst = []
        lst.append('<CPE(')
        lst.append('id=' + self.id)
        lst.append('product=' + self.product)
        lst.append('vendor=' + self.vendor)
        lst.append(')>')
        return ''.join(lst)


class Link(Base):
    __tablename__ = 'link'
    cve_id = Column(String,
                    ForeignKey('cve_table.id'),
                    primary_key=True)
    cpe_match = Column(String,
                       ForeignKey('cpe_table.id'),
                       primary_key=True)


class DataHandler(object):
    def __init__(self):
        self.engine = create_engine('sqlite:///data.db')
        Base.metadata.create_all(self.engine)
        Session = sessionmaker()
        Session.configure(bind=self.engine)
        self.session = Session()

    def generate_cve(self, data_entry):
        """
        Generates CVE table entry, as defined by the class
        above.

        :param data_entry: json formatted substring
        from json.load

        :return: CVE
        """
        cve = data_entry['cve']
        cve_id = cve['CVE_data_meta']['ID']
        desc = str(cve['description'])
        last_mod_date = data_entry['lastModifiedDate']
        pub_date = data_entry['publishedDate']

        try:
            # not all CVEs have scores apparently.
            score = data_entry['impact']['baseMetricV3']['impactScore']
        except:
            score = None
            pass

        return CVE(id=cve_id,
                   desc=desc,
                   pub_date=pub_date,
                   last_mod_date=last_mod_date,
                   score=score)

    def generate_cpes(self, data_entry):
        """
        Generates a list of cpe_matches from the
        data entry provided.

        :param data_entry: json formatted substring
        from json.load

        :return: list of cpe_match strings.
            e.g ["cpe:2.3:a:jenkins:openid:*:*:*:*:*:jenkins:*:*"]
        """
        lst = []
        for node in data_entry['configurations']['nodes']:
            if 'children' in node:
                for item in node['children']:
                    lst.extend(self.__iterate_cpe_match__(item))
            else:
                lst.extend(self.__iterate_cpe_match__(node))

        return lst

    def querry_cpe(self, vendor, product):
        """
        Queries the database for any entry where the
        requested vendor or product occurs.

        :param vendor: (str)
        :param product: (str)
        :return: a string of space seperated CVE IDs.
        """
        lst =[]
        if vendor and product:
            query = self.session.query(CPE).filter(CPE.product.like(str(product)),
                                                   CPE.vendor.like(str(vendor)))
        elif vendor:
            query = self.session.query(CPE).filter_by(vendor=vendor)
        elif product:
            query = self.session.query(CPE).filter_by(product=product)

        for result in query:
            lst.extend([cve.id for cve in result.cve_lst])
            print(result.product)
        lst = list(dict.fromkeys(lst)) #removes duplicates
        return ' '.join(lst)

    def querry_cve(self, id):
        """
        Encapuslates a standard session query using sqlalchemy.

        :param id: (str) CVE id
        :return: json formated string with:
            - CPEs
            - cvss3 score (if not null)
            - description
            - dates
        """
        dct = {}
        cve = self.session.query(CVE).filter_by(id = id).first()
        dct['cpe'] = ' '.join([cpe.id for cpe in cve.cpe])
        dct['cvss3'] = cve.score
        dct['desc'] = cve.desc
        dct['publication date'] = cve.pub_date
        dct['last updated'] = cve.last_mod_date
        return json.dumps(dct,indent=2)

    def add(self, data_entry):
        """
        Generates table entries for above tables
        from entry standard to json file provided
        for the exercise
        :param data_entry: (str) string in json format
        :return: None
        """
        cve = self.generate_cve(data_entry)
        cpes = self.generate_cpes(data_entry)
        for cpe_match in cpes:
            existing_cpe = self.session.query(CPE).filter_by(id = cpe_match).first()
            if existing_cpe:
                existing_cpe.cve_lst.append(cve)
            else:
                product = ' '.join(cpe.CPE(cpe_match).get_product())
                vendor = ' '.join(cpe.CPE(cpe_match).get_vendor())
                new_cpe = CPE(id=cpe_match,product=product,vendor=vendor)
                new_cpe.cve_lst.append(cve)
                self.session.add(new_cpe)
        self.session.add(cve)

    def __iterate_cpe_match__(self, item):
        lst = []
        for val in item['cpe_match']:
            t_str = val['cpe23Uri']
            lst.append(t_str)
        return lst

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("json_file", help='json file to be converted')
    args = parser.parse_args()
    if os.path.exists('data.db'):
        answer = input( 'data,db already exists should i overwrite? y/N')
        if answer not in ['Y','y']:
            sys.exit()
    subprocess.run(['rm', 'data.db'])
    dh = DataHandler()
    with open(args.json_file,'r') as json_file:
        data = json.load(json_file)
        for enum,entry in enumerate(data):
            dh.add(entry)
            print(enum, '/', len(data))
        dh.session.commit()

