import torch


def cross_entropy_masked(og_label, pred, loss_fn):
    """
    Cross entropy loss function, but only for the masked values.
    :param og_label: The original label
    :param pred: The prediction
    :param loss_fn: The loss function to use (cross entropy)
    :return: The loss between the original label and the prediction for the masked values
    """
    mask = ((og_label + 1).clip(0, 1)).type(torch.long)
    og_label_masked = og_label[mask == 1]
    predictions_masked = pred[mask == 1]
    return loss_fn(predictions_masked, og_label_masked)
