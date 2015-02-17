from setuptools import setup

setup(name='GithubEmailHook',
      version='1.0',
      description='Github Email Hook',
      author='David Shea',
      author_email='dshea@redhat.com',
      url='http://github.com/dashea/github-email-hook',
      packages=['github_email_hook'],
      install_requires=open("requirements.txt").readlines()
     )
