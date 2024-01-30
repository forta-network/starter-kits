
from os import path


class FileSystem:
  def exists(self, file_path: str) -> bool:
    return path.isfile(file_path)