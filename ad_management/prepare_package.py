#!/usr/bin/env python3
import json
import os
import tarfile
import datetime
import io
import sys
from git import Repo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ad_management.common import SCION_ROOT, PACKAGE_DIR_PATH


def get_package_name(repo, commit):
    now = datetime.datetime.now()
    package_name = "scion_{}_{}.tar".format(commit.hexsha[:8],
                                            now.strftime("%d_%m_%y"))
    return package_name


def get_package_metadata(repo, commit):
    now = str(datetime.datetime.now())
    metadata = {'commit': commit.hexsha,
                'date': now,
                }
    return metadata


def prepare_package(out_dir=PACKAGE_DIR_PATH, config_paths=None):
    """
    config_paths -- list of paths to topology dirs

    """
    repo = Repo(SCION_ROOT)
    assert not repo.bare

    if len(sys.argv) > 1:
        commit_hash = repo.commit(sys.argv[1])
    else:
        commit_hash = repo.head.commit.hexsha

    commit = repo.commit(commit_hash)
    package_name = get_package_name(repo, commit)

    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)

    package_path = os.path.join(out_dir, package_name)

    package_prefix = 'scion-package/'
    with open(package_path, 'wb') as out_fh:
        repo.archive(out_fh, prefix=package_prefix)

    # Append configs
    if config_paths is not None:
        if isinstance(config_paths, str):
            config_paths = [config_paths]
        with tarfile.open(package_path, 'a') as tar_fh:
            for path in config_paths:
                assert os.path.isdir(path)
                dirname = os.path.basename(path)
                arcname = os.path.join(package_prefix, 'topology', dirname)
                tar_fh.add(path, arcname)

    # Append metadata
    metadata = get_package_metadata(repo, commit)
    metadata['with_config'] = (config_paths is not None)
    metadata_bytes = bytes(json.dumps(metadata, indent=2), 'utf-8')
    metadata_stream = io.BytesIO(metadata_bytes)
    with tarfile.open(package_path, 'a') as tar_fh:
        meta_tarinfo = tarfile.TarInfo('META')
        meta_tarinfo.size = len(metadata_bytes)
        tar_fh.addfile(meta_tarinfo, metadata_stream)

    print('Package created:   {}'.format(package_name))
    return package_path


def main():
    prepare_package(config_paths='/home/tonyo/scion_ethz/scion/topology/ISD1')


if __name__ == '__main__':
    main()
